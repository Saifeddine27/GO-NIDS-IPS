# Go-NIDS/IPS

Salut !  J'ai développé ce petit projet de NIDS (Network Intrusion Detection System) en Go pour expérimenter avec l'analyse de trafic réseau en temps réel. 
L'idée est d'écouter les paquets qui circulent et de lever des alertes dès qu'un comportement suspect est détecté, tout en gardant un outil léger et performant.

## Ce que l'outil sait détecter

Le moteur d'analyse surveille actuellement les comportements suivants :
- **Port scan** : Repère quand quelqu'un scanne vos ports un peu trop vite (Warning à 5 ports, Critical à 15 ports).
- **SYN flood** : Détecte les dénis de service (DoS) basés sur des avalanches de paquets SYN (100+ paquets purs en 5s).
- **Brute force** : Surveille les tentatives de connexion répétées sur les ports critiques (SSH, Telnet, FTP, RDP, VNC).
- **UDP flood** : Détecte les anomalies de trafic UDP (200+ paquets en 5s).
- **Ping sweep** : Repère les tentatives de découverte d'hôtes sur le réseau via ICMP.

Toutes les alertes générées sont archivées proprement dans un fichier de logs JSON (avec rotation automatique à 10 MB).

---

## Prérequis

Comme l'outil doit lire des paquets réseau bruts ("raw sockets"), il s'appuie sur `libpcap` et est pensé pour tourner sous **Linux**.

Voici ce dont vous aurez besoin sous Debian/Ubuntu :

```bash
sudo apt update
sudo apt install -y golang libpcap-dev
```

Assurez-vous également d'avoir une version récente de Go (>= 1.22) :
```bash
go version
```

---

## Installation et Utilisation

Pour récupérer et lancer le projet chez vous :

```bash
# On clone le repo
git clone https://github.com/Saifeddine27/nids-go.git
cd nids-go

# On télécharge les dépendances
make setup

# On compile le binaire dans bin/nids
make build
```

Pour lancer la détection, utilisez la commande suivante (les droits `sudo` sont obligatoires pour pouvoir écouter l'interface réseau en mode raw) :

```bash
sudo ./bin/nids
# ou directement avec : make run
```

Au démarrage, le programme liste les interfaces réseau disponibles et demande laquelle écouter :

```
Interfaces réseau disponibles :
  [0] eth0 (Ethernet)
  [1] lo (Loopback)
  [2] wlan0 (Wi-Fi)

  Entrez le nom de l'interface à écouter (ex: eth0, lo, wlan0) ou 'any' pour toutes :
```

Entrer le nom de l'interface souhaitée (ex: `eth0`) ou `any` pour capturer sur toutes les interfaces.

---

## Configuration

Les seuils de détection et les fenêtres de temps sont personnalisables via le fichier `config.yaml` à la racine du projet. Cela permet d'ajuster la sensibilité du NIDS à la volée, sans recompiler :

```yaml
alert_cooldown_seconds: 10

port_scan:
  window_seconds: 10
  threshold_warning: 5
  threshold_critical: 15
# (voir le fichier config.yaml pour toutes les options : syn_flood, brute_force, etc.)
```

---

## Alertes

Les alertes s'affichent dans le terminal en temps réel :

```
[!] CRITICAL | PORT_SCAN      | 192.168.1.42 | 17 ports uniques ciblés en moins de 10s
[!] CRITICAL | SYN_FLOOD      | 10.0.0.5     | 103 paquets SYN en moins de 5s
[-] WARNING  | PING_SWEEP     | 192.168.1.10 | 5 hôtes uniques pingués en moins de 10s
```

Elles sont aussi enregistrées dans `alerts.json` (format JSON Lines). Le fichier est automatiquement archivé sous `alerts_YYYYMMDD_HHMMSS.json` dès qu'il dépasse 10 MB.

---

## Prévention Active (IPS)

En plus de détecter les attaques, le moteur agit comme un IPS (Intrusion Prevention System). Lorsqu'une attaque est jugée "CRITICAL", l'IP de l'attaquant est **automatiquement bloquée** au niveau du pare-feu Linux (`iptables`) pendant 10 minutes.

Pour vérifier que le blocage fonctionne bien lors de vos tests, vous pouvez afficher la liste des IPs actuellement bannies par la machine avec cette commande :

```bash
sudo iptables -L INPUT -v -n | grep DROP
```
*(Le déblocage se fait tout seul en arrière-plan une fois le temps d'exclusion écoulé).*

---

## Tests Unitaires

Le moteur de détection dispose d'une suite de tests pour garantir sa fiabilité de détection sans avoir à brancher l'outil sur un vrai réseau hostile. Le système simule l'injection de paquets frauduleux (SYN Flood, Ping Sweep, etc.) et valide mathématiquement que les alertes et les blocages sont déclenchés correctement.

Pour lancer les tests :
```bash
make test
```

---

## Structure du projet

```
nids-go/
├── cmd/nids/          # Point d'entrée principal
├── internal/
│   ├── alert/         # Journalisation des alertes (JSON + rotation)
│   ├── capture/       # Capture de paquets (libpcap)
│   ├── config/        # Chargement de la configuration YAML
│   ├── engine/        # Moteur de détection (heuristiques)
│   ├── filter/        # Filtrage du trafic bruit (DNS, DHCP, NTP...)
│   ├── ips/           # Prévention (blocage IP)
│   └── parser/        # Parsing des paquets réseau
└── Makefile
```

---

## Dépendances Go

Le projet repose sur très peu de dépendances externes pour rester le plus standard possible :
| Package | Rôle |
|---|---|
| `github.com/google/gopacket` | Permet de capturer et de parser les paquets réseau très facilement. |
| `gopkg.in/yaml.v3` | Gère la lecture du fichier `config.yaml`. |

Elles sont installées automatiquement quand vous faites un `make setup`.

## Nettoyage

```bash
make clean
```

Supprime le binaire compilé dans `bin/`.
