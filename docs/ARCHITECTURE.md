# WarrenVPN — Architettura e Riferimento Funzionale

WarrenVPN è un client OpenVPN completo, con interfaccia grafica, per il desktop
Linux. È costruito sui meccanismi nativi della piattaforma: un demone di sistema
privilegiato attivato via **D-Bus** e autorizzato per-azione da **polkit**, una GUI
**GTK4 + libadwaita**, persistenza delle credenziali nel **Secret Service**
(libsecret), DNS via **systemd-resolved**, un kill-switch **nftables**, e integrazione
con **systemd**/**logind** per il ciclo di vita del processo e degli eventi di sessione.

Licenza: **GPL-2.0-only** (vedi `COPYING`).

Questo documento descrive l'architettura, i sottosistemi, le invarianti di sicurezza,
la matrice delle capacità (cosa è implementato / parziale / pianificato) e il registro
dei rischi. È un MVP reale e funzionante; questo testo distingue onestamente ciò che è
implementato da ciò che è rinviato (vedi `docs/DECISIONS.md`).

---

## 1. Modello in tre processi

WarrenVPN si articola in tre eseguibili con un confine di privilegio netto:

- **`warrenvpnd`** — il demone di sistema privilegiato (root, capability-scoped),
  attivato via D-Bus sul system bus `net.warrenvpn.WarrenVPN1`. È **l'unico confine di
  sicurezza**. Pilota OpenVPN direttamente tramite la *management interface* di
  OpenVPN, un processo OpenVPN transitorio per connessione.
- **`warrenvpn`** — la GUI GTK4 + libadwaita, client **non privilegiato**.
- **`warrenvpnctl`** — la CLI, client **non privilegiato**.

GUI e CLI non hanno alcun privilegio: ogni operazione sensibile passa per il demone,
che la autorizza via polkit e la riesegue da zero (re-parsing, ri-classificazione,
verifica) senza mai fidarsi del client.

### Perché il controllo diretto di OpenVPN

WarrenVPN pilota OpenVPN direttamente via la sua *management interface*
(`state`/`bytecount`/`password`/`cr-response`/`hold`/`signal`) invece di delegare a un
plugin NetworkManager. Questa scelta (decisa, vedi `docs/DECISIONS.md`) è ciò che
abilita l'intero set di funzionalità di autenticazione interattiva, le statistiche
live, gli hook DNS/route e il controllo fine del timing del kill-switch: un plugin di
desktop nasconderebbe il canale di management e renderebbe impossibili quasi tutte
queste capacità. Il costo accettato è che la logica DNS, route, kill-switch e anti-leak
è scritta e mantenuta dal progetto.

---

## 2. Modello di sicurezza (TCB)

Il demone **non si fida mai del client**. Ogni metodo D-Bus privilegiato è autorizzato
via polkit, e tutto ciò che il client asserisce viene riverificato lato server.

### Autorizzazione per-azione (polkit)

Ogni metodo privilegiato invoca `CheckAuthorization` con il chiamante D-Bus come
soggetto. Le azioni (prefisso `net.warrenvpn.`) sono distinte e con policy diverse:

| Azione | Uso | Policy tipica |
|---|---|---|
| `net.warrenvpn.connect` | avvio di una connessione da config *safe* | `allow_active` (nessun prompt) |
| `net.warrenvpn.connect-unsafe` | avvio di una config *unsafe* (può eseguire codice come root) | auth admin |
| `net.warrenvpn.install-config` | import/installazione di una configurazione | auth admin |
| `net.warrenvpn.manage-daemon` | operazioni di gestione del demone | auth admin |
| `net.warrenvpn.killswitch` | ripristino connettività / kill-switch | lenient |
| `net.warrenvpn.connect-at-boot` | (pianificato) connessione al boot | auth admin |
| `net.warrenvpn.update-install` | (pianificato) self-update | auth admin |

### Invarianti del Trusted Computing Base

Il TCB è il parser/classificatore di configurazioni (`ovpn-config`) più le primitive
atomiche di scrittura file del demone. Le invarianti chiave:

1. **Ri-classificazione lato server.** Il demone ri-parsa e ri-classifica ogni
   configurazione come *safe* o *unsafe* — dove *unsafe* significa che la config può
   far eseguire codice come root (direttive tipo `up`/`down`/`plugin`/`script-security`
   ecc.). Il verdetto della GUI non viene **mai** ritenuto attendibile.
2. **Classificatore su nome-opzione normalizzato.** La classificazione confronta il
   nome di opzione *normalizzato* (dopo `unquote()`), così che evasioni tramite
   quoting/escape (`"up"`, `'plugin'`, `u\p`) non possano sfuggire all'allowlist. È un
   componente puro e pesantemente testato.
3. **Copie shadow root-owned, scritte atomicamente.** L'unica copia di configurazione
   contro cui OpenVPN viene mai lanciato è una copia shadow di proprietà di root,
   scritta in modo atomico (file temporaneo + rename, `O_NOFOLLOW`, `fchown`/`fchmod`
   su fd) dopo la classificazione lato server, sotto `/var/lib/warrenvpn`.
4. **Allowlist delle opzioni OpenVPN** nella costruzione dell'argv (anti
   option-injection), ambiente pulito prima di ogni exec.
5. **Scoping per chiamante.** Il demone deriva la radice dello store dallo uid del
   chiamante *autenticato* (`GetConnectionUnixUser`), non dal proprio; elenco,
   sanitizzazione e avvio sono limitati al chiamante. Il contenuto della config è
   inviato come **byte** letti come l'utente: il demone non apre mai un percorso
   controllato dal client come root.
6. **`config_id` validato** (32 cifre esadecimali minuscole) al confine dello store,
   per chiudere il path traversal.
7. **`--script-security`** minimo: `1` per le config safe; `2` solo per le safe e solo
   quando l'helper up/down fidato è installato (l'unico script eseguito è il nostro).

Il demone logga su journald con campi strutturati e segreti redatti. È attivato via
D-Bus su richiesta (systemd `Type=dbus`); l'uscita in idle con riattivazione è
**pianificata** (vedi la matrice nella Sezione 5), non ancora implementata.

---

## 3. Crate del workspace Rust

| Crate | Ruolo |
|---|---|
| **`ovpn-config`** | Tokenizer/parser delle config OpenVPN + classificatore safe/unsafe. È il **TCB**: il suo verdetto decide se una config può avviare OpenVPN come root senza prompt admin. Puro, fortemente testato, indurito contro l'evasione via quoting/escape del nome opzione. |
| **`warrenvpn-common`** | Unica sorgente di verità per l'identità: app-id, nomi D-Bus, id azioni polkit, percorsi del filesystem. Il rebrand consiste nel modificare questa crate più i template di `packaging/`. |
| **`warrenvpn-core`** | Logica di demone indipendente dal trasporto: parsing del protocollo di management (inclusi i prompt di auth e SCRV1), costruttore dell'argv di OpenVPN, store delle copie shadow root-owned, parsing del DNS pushato, costruttore del ruleset nftables del kill-switch. |
| **`warrenvpnd`** | Il demone di sistema privilegiato (`net.warrenvpn.WarrenVPN1`). L'unico confine di sicurezza: polkit per metodo, ri-classificazione lato server, scoping dello store per chiamante, oggetti `Connection` live, DNS via systemd-resolved, kill-switch, gestione dello shutdown via logind. |
| **`warrenvpn-gui`** | Front-end GTK4 + libadwaita (`warrenvpn`): lista/import/connect, stato live, tray (StatusNotifierItem), dialogo credenziali + persistenza libsecret, impostazioni per-config. |
| **`warrenvpn-cli`** | `warrenvpnctl`: controllo headless (list/status/import/connect/disconnect/remove/recover), con autenticazione interattiva da terminale. |

---

## 4. Sottosistemi

### (1) Demone privilegiato — `warrenvpnd`

Servizio systemd attivato via D-Bus alla prima chiamata. Espone metodi tipizzati su
`net.warrenvpn.WarrenVPN1` (system bus), oggetto `/net/warrenvpn/WarrenVPN1`, con le
interfacce `.Manager` (gestione globale: lista, installazione, recover, segnali) e
`.Connection` (una per tunnel live: stato, byte-counter, `ProvideCredentials`,
disconnect). È l'intero contratto di privilegio.

Hardening dell'unit: capability scoping (`CAP_NET_ADMIN`/`CAP_NET_RAW`, più
`CAP_SETUID`/`CAP_SETGID` per il privilege-drop interno di OpenVPN), `ProtectSystem`,
`PrivateTmp`, `ReadWritePaths` mirati su `/run/warrenvpn`, `/var/lib/warrenvpn` e
`/etc/warrenvpn`.

### (2) GUI non privilegiata — `warrenvpn` (GTK4 + libadwaita)

Possiede tutta la UX: finestra principale con lista delle configurazioni, import,
connect/disconnect, stato live e byte-rate, log, dialoghi di autenticazione
(login/passphrase/challenge), impostazioni per-config. Registra uno
StatusNotifierItem (tray); chiudere la finestra nasconde nel tray, l'app resta viva,
Quit esce. Legge/scrive credenziali via libsecret. È single-instance via GApplication.
Il refresh è guidato dai segnali del demone (`net.warrenvpn.WarrenVPN1.Manager`)
inoltrati al loop GTK, con un poll a 2 s come fallback.

### (3) CLI — `warrenvpnctl`

Controllo headless dello stesso demone. Verbi:

```
warrenvpnctl list | status | import <file.ovpn>
             connect <name> [--killswitch] | disconnect <name>
             remove <name> | recover
```

Esegue l'auth interattiva da terminale (username/password, passphrase, challenge) e
rifiuta di avviare config che eseguono comandi senza conferma.

### Ciclo di vita della connessione

Su `StartConnection` il demone re-deriva safe/unsafe dai byte su disco, autorizza con
`connect` (safe) o `connect-unsafe` (unsafe), costruisce l'argv con allowlist e avvia
OpenVPN con `--management` su un socket unix-domain root-owned in `/run/warrenvpn`
(tmpfs, 0600) più un password file `O_EXCL`. Il client di management nel demone parsa
gli stati (`state on`), i byte-counter (`bytecount`) e i prompt di autenticazione, ed
emette segnali alla GUI/CLI. La disconnessione avviene via `signal SIGTERM` /
terminazione del processo, con un marker expect-disconnect per distinguere le
disconnessioni attese da quelle inattese.

> **Nota onesta (rinviato):** oggi OpenVPN è lanciato come processo figlio diretto del
> demone, non come scope systemd transitorio. Di conseguenza i tunnel **non
> sopravvivono** a un riavvio del demone, e l'adozione di connessioni già in esecuzione
> non è ancora implementata (`TODO(scope)` in `connection.rs`). Vedi §6.

### Store delle configurazioni

Le configurazioni importate vengono tokenizzate, normalizzate e scritte come copie
shadow root-owned sotto `/var/lib/warrenvpn`, scritte atomicamente dopo la
classificazione lato server. L'identità di una config è un id immutabile (32 hex), così
che le operazioni di gestione restino stabili. Lo stato runtime per-connessione vive in
`/run/warrenvpn`.

### DNS — systemd-resolved

Un helper up/down fidato e root-owned (`packaging/scripts/warrenvpn-updown`) cattura
`dev` e i `foreign_option_*` pushati. Il demone li legge su `CONNECTED` e applica il
DNS via `org.freedesktop.resolve1` (`SetLinkDNS`/`SetLinkDomains`/`SetLinkDefaultRoute`
sull'indice del link tun), ripristinando in fase di teardown. `warrenvpn-core::dns`
parsa i valori `dhcp-option` pushati (testato) e risolve l'indice del link tun da
`/sys/class/net`.

### Kill-switch — nftables

`warrenvpn-core::killswitch::build_ruleset` genera una tabella dedicata
`inet warrenvpn` con `policy drop`, che consente solo loopback, il device tun,
l'endpoint del server VPN (famiglia corretta, da `trusted_ip`/`trusted_port`/`proto`) e
i rinnovi DHCP/DHCPv6. Essendo `inet` + default-drop, l'IPv6 non-tunnel è bloccato
(chiude il leak IPv6). C'è anche una catena FORWARD (drop, solo tun + established) così
che anche l'egress instradato (Docker/VM) sia bloccato mentre armato.

Proprietà di lifecycle:

- **Fail-closed.** Un kill-switch richiesto ma non armabile (nessun endpoint, fallimento
  di `nft`) abbatte la connessione invece di proseguire non protetta; `StartConnection`
  rifiuta `killswitch=true` in partenza se `nft` è assente.
- **Reference-counted.** La singola tabella installa l'unione di ogni tunnel armato; il
  teardown avviene solo all'uscita dell'ultimo tunnel armato.
- **Disarma solo su disconnessione attesa**; un drop inatteso mantiene l'egress
  bloccato finché l'utente non riconnette o invoca `RecoverNetwork`.
- **Boot-recovery obbligatorio.** L'unit `warrenvpn-recover.service` (abilitata dal
  pacchetto, ordinata `Before=warrenvpnd.service`) azzera in modo idempotente una
  tabella lasciata da un crash, così che il kill-switch non possa mai isolare la
  macchina. L'azione "Ripristina connettività" è esposta in tray e via
  `warrenvpnctl recover`.

### Credenziali — Secret Service

Persistenza via libsecret (gnome-keyring / kwallet-bridge): salvataggio password,
auto-fill alla riconnessione, gruppi di credenziali. Il recupero non interattivo non
forza mai l'unlock del keyring.

### Eventi di sistema — logind

Teardown pulito dei tunnel al logout/shutdown via logind.

---

## 5. Matrice delle capacità

Stato: **implementato** (funzionante nell'MVP), **parziale** (presente con limiti),
**pianificato** (rinviato, vedi `docs/DECISIONS.md` — non ancora fatto).

### Architettura e privilegio

| Capacità | Sottosistema | Stato |
|---|---|---|
| Demone di sistema privilegiato attivato via D-Bus | Privilegio | implementato |
| Autorizzazione polkit per-azione (azioni distinte safe/unsafe/admin) | Privilegio | implementato |
| Ri-classificazione safe/unsafe lato server | TCB | implementato |
| Copie shadow root-owned, scritte atomicamente | TCB | implementato |
| Allowlist opzioni / argv puliti / ambiente sanitizzato | TCB | implementato |
| Scoping dello store per uid del chiamante | Privilegio | implementato |
| Logging strutturato su journald con segreti redatti | Privilegio | implementato |
| Sanitizzazione della config per log/display | Sicurezza | implementato |
| Idle-exit del demone | Privilegio | pianificato |
| Preferenze forzate / managed (enterprise) | Config | pianificato |

### Configurazione

| Capacità | Sottosistema | Stato |
|---|---|---|
| Tokenizer/parser config OpenVPN (quote/escape/inline) | Config | implementato |
| Import `.ovpn` (drag-drop, doppio-click, CLI) | Config/UI | implementato |
| Normalizzazione + path-stripping in copia shadow | Config | implementato |
| Classificazione safe/unsafe + prompt di fiducia per config con script | Config/Sicurezza | implementato |
| Rimozione config + relative credenziali | Config/Auth | implementato |
| Impostazioni per-config (toggle kill-switch + auto-connect) | Config | implementato |
| Spostamento config tra scope (private/shared) | Config | pianificato |

### Connessione e autenticazione

| Capacità | Sottosistema | Stato |
|---|---|---|
| Controllo di OpenVPN via management interface | Connessione | implementato |
| Connect / disconnect | Connessione | implementato |
| Stato connessione live + byte-counter | Connessione/UI | implementato |
| Cattura e display del log | UI | implementato |
| Auth username/password | Auth | implementato |
| Passphrase chiave privata | Auth | implementato |
| Static challenge (SCRV1) | Auth | implementato |
| Dynamic challenge (CRV1) | Auth | implementato |
| Web-auth / SSO (OPEN_URL nel browser) | Auth | implementato |
| Persistenza credenziali (Secret Service) | Auth | implementato |
| Auto-connect al lancio | Connessione | implementato |
| Riconnessione dopo disconnessione inattesa | Connessione | parziale (OpenVPN ping-restart copre il caso comune) |
| Sopravvivenza dei tunnel a un riavvio del demone + adozione | Connessione | pianificato |
| Connect-at-boot prima del login | Connessione | pianificato |
| PKCS#11 PIN / CR_TEXT | Auth | pianificato |

### DNS e rete

| Capacità | Sottosistema | Stato |
|---|---|---|
| DNS via systemd-resolved (apply/revert su link tun) | DNS | implementato |
| Parsing del DNS pushato (`dhcp-option`) | DNS | implementato |
| Split-DNS via routing domains di resolved | DNS | implementato |
| Fallback resolvconf / raw `/etc/resolv.conf` | DNS | pianificato |

### Kill-switch e protezione

| Capacità | Sottosistema | Stato |
|---|---|---|
| Kill-switch nftables egress-only, fail-closed | KillSwitch | implementato |
| Blocco IPv6 non-tunnel + egress instradato (FORWARD) | KillSwitch | implementato |
| Distinzione disconnessione attesa/inattesa | KillSwitch | implementato |
| Unit di boot-recovery obbligatoria | KillSwitch | implementato |
| Azione "Ripristina connettività" (tray + CLI) | KillSwitch/UI | implementato |
| Protezione della finestra di connect (pre-connect lockdown) | KillSwitch | implementato |
| Teardown pulito su logout/shutdown (logind) | Rete | implementato |

### UI

| Capacità | Sottosistema | Stato |
|---|---|---|
| Finestra principale GTK4 + libadwaita | UI | implementato |
| Tray StatusNotifierItem (richiede estensione AppIndicator su GNOME) | UI | implementato |
| Dialoghi di autenticazione (login/passphrase/challenge) | UI | implementato |
| Refresh guidato dai segnali del demone | UI | implementato |
| Internazionalizzazione (i18n) | UI | pianificato |

### Distribuzione e aggiornamenti

| Capacità | Sottosistema | Stato |
|---|---|---|
| Pacchetto nativo Arch (makepkg / PKGBUILD) | Packaging | implementato |
| Clean-room AUR PKGBUILD con sorgente versionata | Packaging | pianificato |
| Pacchetti `.deb` / `.rpm` | Packaging | pianificato |
| Self-update in-app | Updates | pianificato |

---

## 6. Stato di qualità

- **75 test unitari** passano (`cargo test --workspace`): 28 in `ovpn-config`, 43 in
  `warrenvpn-core`, 4 in `warrenvpn-common`.
- **clippy** senza warning (`cargo clippy --workspace --all-targets`).
- **5 smoke test end-to-end** passano, eseguiti **senza root** e **senza una VPN
  reale**, pilotando il demone su un session bus privato contro un fake OpenVPN in
  Python:
  - `scripts/smoke-warrenvpnd.sh` — install/classify/sanitize di una config;
  - `scripts/smoke-connect.sh` — ciclo di vita del connect + stato live;
  - `scripts/smoke-auth.sh` — auth username/password (asserisce le risposte esatte sul
    management socket);
  - `scripts/smoke-sc.sh` — static challenge (SCRV1);
  - `scripts/smoke-cli.sh` — `warrenvpnctl` end-to-end.

Le invarianti security-critical (il parser, `unquote`, `escape_mgmt_value`, le
scritture atomiche dello shadow store, il ruleset del kill-switch) sono coperte da test
unitari; il percorso DNS end-to-end e l'applicazione del ruleset nel kernel richiedono
un tun reale e privilegi, quindi non sono esercitati dagli smoke test in-repo (parser e
lookup dell'ifindex sì).

---

## 7. Build, pacchettizzazione e requisiti

### Build

```sh
cargo build --release          # workspace (ciò che il pacchetto spedisce)
cargo test --workspace         # tutti i test unitari
cargo clippy --workspace --all-targets
```

### Pacchetto / installazione su Arch

```sh
cd packaging/arch && makepkg -si
```

Il pacchetto installa: il demone (`/usr/lib/warrenvpn/warrenvpnd`), la GUI
(`/usr/bin/warrenvpn`), la CLI (`/usr/bin/warrenvpnctl`), il servizio D-Bus di sistema +
la sua config bus, la policy polkit (`net.warrenvpn.policy`), le unit systemd (demone +
`warrenvpn-recover.service`), sysusers (gruppo `warrenvpn`), tmpfiles, l'helper
up/down, il `.desktop`, l'icona e le man page (`warrenvpn.1`, `warrenvpnctl.1`,
`warrenvpnd.8`).

Non serve `sudo systemctl ...`: il demone è **attivato via D-Bus**. La GUI si avvia con
`warrenvpn`, la CLI è `warrenvpnctl`.

### Requisiti

- Toolchain Rust **1.80+** per la build.
- A runtime: **GTK4**, **libadwaita**, **polkit**, **libsecret**, **libnftables**,
  **systemd** (con **systemd-resolved**), **openvpn** e **`/dev/net/tun`**.

---

## 8. Registro dei rischi e questioni aperte

1. **Copia shadow + classificatore safe/unsafe = codice a rischio più alto.** Un bug del
   parser diventerebbe un'escalation di privilegio locale a root (la GUI non
   privilegiata potrebbe chiedere al demone di lanciare OpenVPN root contro una config
   che controlla). Lo stesso parser sta nella GUI e nel demone: il demone DEVE
   rieseguirlo, mai fidarsi della GUI. Mitigazioni in corso: fuzzing (`cargo fuzz`) su
   `Config::parse` + `is_safe`, e l'audit di `unquote()` contro
   `options.c::parse_line()` di OpenVPN, da trattare come gate di release.
2. **GNOME non ha tray nativo.** Su GNOME-Wayland stock non c'è status icon senza
   l'estensione third-party AppIndicator (frizione al primo avvio). La finestra
   principale funge da UI primaria; la policy tray-vs-finestra su GNOME resta aperta.
3. **systemd è di fatto una dipendenza HARD.** Attivazione D-Bus, RuntimeDirectory,
   logind, resolved, recovery oneshot, sysusers, tmpfiles: su un box non-systemd quasi
   nulla funziona come specificato. I fallback DNS resolvconf/raw sono pianificati, non
   ancora a parità funzionale.
4. **polkit + un agent polkit devono essere presenti.** Su headless / WM minimale /
   container / sessione SSH può mancare l'agent che rende i prompt admin: `connect`
   (safe, `allow_active`) funziona, ma le azioni admin falliscono. La modalità di
   fallimento senza agent va specificata.
5. **Secret Service: affidabilità variabile.** Nessun keyring su box headless/minimale;
   il bridge kwallet su KDE è storicamente fragile. È previsto un fallback file-cifrato,
   il cui design della master-key è ancora da definire.
6. **Kill-switch nftables — componibilità.** La tabella dedicata `inet warrenvpn` deve
   coesistere con firewalld/ufw, le regole nat di Docker, libvirt/podman e le zone di
   NetworkManager; un reload di firewalld può riordinare o azzerare le regole. Hazard
   parità-vs-stabilità da governare.
7. **Singolo processo root long-lived = superficie d'attacco da rivedere come insieme.**
   Mitigato da polkit-per-azione, allowlist argv stretta, exec a env pulito, capability
   scoping e direttive di sandbox systemd.
8. **Sopravvivenza al riavvio del demone non ancora implementata.** Finché OpenVPN è
   lanciato come figlio diretto (non come scope systemd transitorio), un riavvio del
   demone interrompe i tunnel e non esiste adozione delle connessioni orfane. È la
   precondizione anche del connect-at-boot e dell'adozione di una tabella kill-switch
   orfana.

Le questioni aperte di prodotto (policy di ri-autorizzazione per-connect, connect-at-boot
prima del login, modello di firma per gli update, profondità delle preferenze enterprise,
privacy del check IP pubblico, openvpn come root pieno vs worker con solo
`CAP_NET_ADMIN`) sono tracciate in `docs/DECISIONS.md`.

---

## 9. Documentazione correlata

- `docs/IPC-CONTRACT.md` — il contratto D-Bus di privilegio/automazione e le regole TCB
  del demone.
- `docs/DECISIONS.md` — decisioni prese, questioni aperte e i fix dalle revisioni
  avversariali.
- `docs/MANUALE-IT.md` — manuale utente in italiano.
