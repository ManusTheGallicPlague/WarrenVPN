# WarrenVPN — Manuale utente

WarrenVPN è un client OpenVPN per Linux con interfaccia grafica,
una riga di comando (`warrenvpnctl`) e un demone di sistema che gestisce la connessione
in modo sicuro tramite polkit. Questo manuale spiega come installarlo e usarlo al
meglio.

---

## 1. Che cos'è e come funziona (in breve)

WarrenVPN è composto da tre parti che collaborano:

- **`warrenvpn`** — l'app grafica (GTK4) con cui importi le configurazioni, ti connetti
  e vedi lo stato. Vive anche nell'area di notifica (tray).
- **`warrenvpnctl`** — il comando da terminale, per usare WarrenVPN senza interfaccia
  grafica o in script.
- **`warrenvpnd`** — il *demone* privilegiato. È l'unico componente che gira con
  privilegi elevati: avvia OpenVPN, configura DNS e rotte, gestisce il kill-switch.
  Si avvia **da solo** quando serve (attivazione D-Bus); non devi mai lanciarlo a
  mano.

**Modello di sicurezza:** il demone autorizza ogni operazione tramite **polkit**.
*Connettere/disconnettere* non chiede la password (basta una sessione attiva);
*importare/rimuovere* configurazioni o gestire impostazioni di sistema richiede
l'autenticazione di amministratore. Le configurazioni vengono ricontrollate dal
demone e salvate in copie protette di proprietà di root: l'app non può far eseguire
codice come root senza il tuo consenso.

---

## 2. Requisiti

- Una distribuzione Linux con **systemd** (WarrenVPN è pensato per systemd).
- **OpenVPN** installato (per connessioni reali).
- **polkit** con un agente attivo (presente di default su GNOME, KDE, ecc.).
- Per il DNS automatico: **systemd-resolved** attivo (consigliato).
- Per il kill-switch: **nftables** (il comando `nft`).
- Un ambiente desktop. Su **GNOME** l'icona nel tray richiede l'estensione
  *AppIndicator/AppIndicator Support* (su KDE/Plasma e molti altri funziona nativa).

Le dipendenze vengono installate automaticamente dal pacchetto (vedi sotto).

---

## 3. Installazione

### Arch Linux / derivate

```bash
sudo pacman -U warrenvpn-0.0.1-1-x86_64.pkg.tar.zst
```

`pacman` scaricherà automaticamente le dipendenze mancanti (gtk4, libadwaita,
polkit, openvpn, nftables, …). Al termine:

- la GUI è disponibile come **WarrenVPN** nel menu Applicazioni (o col comando `warrenvpn`);
- il comando `warrenvpnctl` è nel `PATH`;
- il demone è registrato e si avvierà al primo utilizzo;
- viene abilitata `warrenvpn-recover.service`, una rete di sicurezza che azzera un
  eventuale kill-switch rimasto attivo dopo un crash/riavvio.

Per disinstallare:

```bash
sudo pacman -R warrenvpn
```

Le tue configurazioni personali (in `~/.local/share/warrenvpn`) e le password salvate
nel portachiavi restano; rimuovile a mano se lo desideri.

---

## 4. Primo avvio

Apri **WarrenVPN** dal menu Applicazioni, oppure:

```bash
warrenvpn
```

La prima volta la lista è vuota: importa una configurazione (Sezione 5).

> Nota: chiudendo la finestra WarrenVPN resta attivo nel **tray** (così le connessioni
> proseguono). Per riaprire la finestra clicca l'icona nel tray o rilancia `warrenvpn`.
> Per uscire del tutto usa **Esci** dal menu del tray.

---

## 5. Importare una configurazione OpenVPN

Hai bisogno di un file `.ovpn` (o `.conf`) fornito dal tuo provider/amministratore.

**Dalla GUI:** premi il pulsante **➕** in alto a sinistra, scegli il file `.ovpn`.
WarrenVPN lo legge, lo classifica e lo mostra in elenco. Per le configurazioni che
contengono script o programmi (potenzialmente pericolosi) verrà richiesta
l'autenticazione di amministratore.

**Dalla riga di comando:**

```bash
warrenvpnctl import ~/percorso/della/config.ovpn        # nome = nome del file
warrenvpnctl import ~/config.ovpn "Ufficio"             # nome personalizzato
```

Una voce contrassegnata **UNSAFE** contiene direttive che eseguono codice come root
(es. `up`, `down`, `plugin`): è normale per alcune VPN aziendali, ma richiederà
privilegi di amministratore sia per l'importazione sia per la connessione.

---

## 6. Connettersi e disconnettersi

**Dalla GUI:** premi **Connetti** sulla riga della configurazione. Lo stato passa a
**● CONNECTED** e il pulsante diventa **Disconnetti** (rosso). Lo stato si aggiorna
in tempo reale.

**Dalla riga di comando:**

```bash
warrenvpnctl connect "Ufficio"               # connette e segue lo stato
warrenvpnctl connect "Ufficio" --killswitch  # connette con kill-switch attivo
warrenvpnctl status                          # connessioni attive e loro stato
warrenvpnctl disconnect "Ufficio"
warrenvpnctl list                            # tutte le configurazioni + stato
```

---

## 7. Autenticazione

WarrenVPN gestisce tutti i metodi comuni. Quando OpenVPN richiede credenziali, la GUI
apre una finestra di dialogo (o `warrenvpnctl` chiede sul terminale):

- **Nome utente e password** — i campi standard.
- **Passphrase della chiave privata** — solo il campo password.
- **Codice/PIN aggiuntivo (static challenge)** — un terzo campo per il token/OTP
  configurato dalla VPN.
- **Challenge dinamico (CRV1)** — un secondo prompt con un codice usa-e-getta dopo
  il primo tentativo.
- **SSO via browser (WEB_AUTH)** — WarrenVPN apre automaticamente il browser sulla
  pagina di accesso del provider; completa lì l'autenticazione (con `warrenvpnctl`
  l'URL viene stampato a schermo).

### Salvare le credenziali

Nella finestra di autenticazione attiva **«Salva nel portachiavi»**: nome utente e
password vengono memorizzati nel **portachiavi** del sistema (GNOME Keyring/KWallet
via Secret Service), legati alla configurazione. Alla connessione successiva WarrenVPN
le inserisce da solo. I codici usa-e-getta (OTP/challenge) non vengono mai salvati.

---

## 8. Impostazioni per configurazione

Nella GUI, premi l'icona **⚙ (ingranaggio)** sulla riga di una configurazione:

- **Kill-switch** — blocca tutto il traffico fuori dalla VPN mentre sei connesso
  (vedi Sezione 9).
- **Connetti all'avvio** — WarrenVPN connette automaticamente questa VPN all'apertura
  dell'app.

Le impostazioni si salvano subito e sono per-configurazione.

---

## 9. Kill-switch (blocco anti-fuga)

Il kill-switch impedisce che il traffico esca dalla rete normale se la VPN cade. Con
il kill-switch attivo, mentre sei connesso **viene bloccato tutto il traffico**
tranne: il tunnel VPN, il server VPN stesso e il loopback. Viene bloccato anche
l'IPv6 non instradato nel tunnel (niente fughe IPv6) e il traffico instradato di
container/macchine virtuali.

- **Attivarlo:** dall'ingranaggio della configurazione (GUI) oppure
  `warrenvpnctl connect <nome> --killswitch`.
- **Disconnessione attesa** (premi tu Disconnetti): il kill-switch viene rimosso e
  la rete torna normale.
- **Disconnessione inattesa** (la VPN cade da sola): il kill-switch **resta attivo**
  per non farti uscire in chiaro. La rete resta bloccata finché non ti riconnetti
  oppure ripristini manualmente.
- **Ripristinare la connettività:**

  ```bash
  warrenvpnctl recover
  ```

> Attenzione: con il kill-switch attivo viene bloccato *tutto* il traffico non-VPN,
> incluso quello di Docker/VM e dei servizi locali verso destinazioni esterne. È il
> comportamento voluto; `warrenvpnctl recover` è la via per sbloccare. Un kill-switch
> rimasto attivo dopo un crash viene comunque azzerato al riavvio.

---

## 10. DNS

Quando ti connetti, WarrenVPN applica i server DNS forniti dalla VPN tramite
**systemd-resolved**, instradando le richieste nel tunnel (niente fughe DNS), e
ripristina la configurazione precedente alla disconnessione. Per il funzionamento
automatico serve `systemd-resolved` attivo:

```bash
systemctl status systemd-resolved
```

---

## 11. Riferimento di `warrenvpnctl`

| Comando | Azione |
|---|---|
| `warrenvpnctl list` | Elenca le configurazioni con stato e flag sicura/UNSAFE |
| `warrenvpnctl status` | Mostra le connessioni attive |
| `warrenvpnctl import <file.ovpn> [nome]` | Importa una configurazione |
| `warrenvpnctl connect <nome\|id> [--killswitch]` | Connette (con auth interattiva) |
| `warrenvpnctl disconnect <nome\|id>` | Disconnette |
| `warrenvpnctl recover` | Rimuove il kill-switch / ripristina la rete |

Vedi anche le pagine di manuale: `man warrenvpn`, `man warrenvpnctl`, `man 8 warrenvpnd`.

---

## 12. Dove sono i file

| Percorso | Contenuto |
|---|---|
| `~/.local/share/warrenvpn/` | Configurazioni personali importate |
| `~/.config/warrenvpn/settings.ini` | Preferenze per-configurazione (kill-switch, auto-connect) |
| `/var/lib/warrenvpn/users/<uid>/` | Copie protette (root) usate per lanciare OpenVPN |
| `/etc/warrenvpn/` | Preferenze imposte dall'amministratore + config condivise |
| Portachiavi del sistema | Credenziali salvate (Secret Service) |

I log del demone sono nel journal di systemd:

```bash
journalctl -u warrenvpnd.service           # log del demone
journalctl -u warrenvpnd.service -f        # in tempo reale
```

---

## 13. Risoluzione dei problemi

**«Servizio non raggiungibile» / la lista non si carica.**
Il demone è attivato via D-Bus; di solito basta riprovare un'azione. Controlla il
journal: `journalctl -u warrenvpnd.service -e`. Verifica che `dbus` e `polkit` siano
attivi.

**Connettere non funziona / resta su CONNECTING.**
Serve `openvpn` installato e un file `.ovpn` valido con un server raggiungibile.
Controlla i log della connessione (riquadro log nella GUI, o il journal).

**Mi chiede sempre la password.**
Attiva «Salva nel portachiavi» nella finestra di autenticazione. Se non viene
ricordata, assicurati che il portachiavi (GNOME Keyring/KWallet) sia sbloccato.

**Il kill-switch ha bloccato la rete e non si sblocca.**
Esegui `warrenvpnctl recover`. Dopo un riavvio si azzera comunque da solo.

**Su GNOME non vedo l'icona nel tray.**
Installa e abilita l'estensione *AppIndicator and KStatusNotifierItem Support*. La
finestra principale funziona comunque (riaprila con `warrenvpn`).

**«kill-switch requested but nftables (nft) is not available».**
Installa `nftables` (`sudo pacman -S nftables`).

**Importazione di una VPN aziendale che chiede privilegi admin.**
Normale per configurazioni *UNSAFE* (con script). Autentica come amministratore.

---

## 14. Limiti noti

- Una connessione **reale** richiede `openvpn` e un tuo file `.ovpn` con un server.
- Il ripristino della rete dopo un kill-switch si fa da `warrenvpnctl recover` (un
  pulsante dedicato nella GUI è in arrivo).
- Per il DNS automatico è consigliato `systemd-resolved`.
- Su GNOME il tray richiede l'estensione AppIndicator.

---

*WarrenVPN è software libero (GPL-2.0). Segnalazioni e suggerimenti sono benvenuti.*
