# Write-Up Challenge IRC Bot - HackTheBox

Ceci est ma solution  pour le challenge du type reverse engineering
Dans le cadre du **Meetup Ambassadors CTF**.

<img width="1778" height="915" alt="image" src="https://github.com/user-attachments/assets/cb6dca02-1fdc-4c56-8ebe-b5cab3a419d9" />


## **Petit aperçu du  challenge**

- **Plateforme** : HackTheBox
- **Catégorie** : Reverse Engineering
- **Difficulté** : Medium
- **Description du chall** : "During a routine check on our servers we found this suspicious binary, but when analyzing it we couldn't get it to do anything. We assume it's dead malware but maybe something interesting can still be extracted from it?"
  
##  **OBJECTIF**

L'objectif est alors de retrouver le flag caché dans le binaire malveillant de type IRC Bot.

##  **FICHIERS FOURNIS**


[Accessibles ici](https://github.com/Patrickleondev/Meetup-Ambassadors-CTF---Reverse-Challenge-Writeup/blob/main/rev_ircbot.zip)  ou dans le repertoire.

Avant de commencer je vous invite à lire sur tout ce qui concerne le [fonctionnement des Malware Botnets IRC](https://www.zscaler.com/fr/blogs/security-research/irc-botnets-alive-effective-evolving) c'est assez instructif.

##  **ÉTAPE 1 : ANALYSE INITIALE**

### **Première Impression**
En ouvrant le dossier, je vois un binaire `ircbot` que j'ai eu à  analyser de manière vraiment statique et approfondie (Assembly + le pseudo-code C) car je n'ai pas pu exécuter le malware, juste focus sur les fonctions dans le code.


<img width="959" height="520" alt="image" src="https://github.com/user-attachments/assets/a379719a-10d9-430b-b6d8-f6970f4b370a" />


### **Analyse du Binaire**

```bash


┌──(kali㉿kali)-[/media/sf_Downloads/rev_ircbot/Meetup-Ambassadors-CTF---Reverse-Challenge-Writeup]
└─$ file ircbot 
ircbot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped                                                                        

```

Cet article vous en dira plus sur les ELF interpreter [via ce lien](https://lwn.net/Articles/631631/).

Ici c'est l'interpreteur ``` /lib64/ld-linux-x86-64.so.2  ``` qui est chargé par le noyau linux à l'exécution du binaire.


le binaire est un exécutable Linux 64-bit, donc typique pour un malware.

---

##  **ÉTAPE 2 : OUVERTURE DANS Mon IDA freeware **

<img width="1919" height="865" alt="image" src="https://github.com/user-attachments/assets/58be06d2-c916-4ea6-86d3-739c99ad21eb" />


### **Découverte des Fonctions Principales**
En analysant la fenêtre "Functions", j'identifie plusieurs fonctions importantes :


Voici en resumé une description de chaque fonction retrouvée:

```
_start()           // qui est bien evidemment le point d'entrée principal
IRC_CONNECT()      //connexion réseau
IRC_READ()         // Lecture de données
IRC_SEND()         // Envoi de données
IRC_PROCESS_READ() // Traitement des commandes
IRC_PRIVMSG()      // Messages privés
FLAG_DECODE()      // Déchiffrement du flag
IRC_EXTERNALCMD()  // Exécution de commandes
```

---

##  **ÉTAPE 3 : ANALYSE DE LA FONCTION START**
<img width="509" height="302" alt="image" src="https://github.com/user-attachments/assets/622472dc-74e9-4ba0-a557-43b0cd3ab93f" />


### **Code Décompilé de `_start()`**

```c
signed __int64 start()
{
  signed __int64 v0; // rax

  __asm { syscall; LINUX - sys_getrandom }
  *(_DWORD *)IRC_SEND_NICK_RANDOM &= 0x7070707u;
  *(_DWORD *)IRC_SEND_NICK_RANDOM |= 0x30303030u;
  if ( (int)IRC_CONNECT(IRC_SEND_NICK_RANDOM, 4, 0) >= 0 )
  {
    IRC_SEND();
    IRC_SEND();
    IRC_SEND();
    while ( 1 )
    {
      IRC_READ();
      IRC_PROCESS_READ();
    }
  }
  v0 = sys_write(1u, IRC_ERROR_TEXT, IRC_ERROR_TEXT_LEN);
  return sys_exit(1);
}
```

### **Analyse et informations que j'ai reteenu pour la suite:**

1. **Génération d'un nombre aléatoire** avec `sys_getrandom`
2. **Modification du nick** avec des masques binaires
3. **Connexion à un serveur IRC** via `IRC_CONNECT()`
4. **Envoi de 3 messages IRC** (probablement NICK, USER, JOIN)
5. **Boucle infinie** de lecture et traitement des commandes

---

## **ÉTAPE 4 : ANALYSE DE LA CONNEXION IRC**

<img width="653" height="218" alt="image" src="https://github.com/user-attachments/assets/59193093-1030-4ba5-ab48-9f623ba2c920" />

### **Fonction `IRC_CONNECT()`**
```c
signed __int64 IRC_CONNECT()
{
  _WORD v1[2]; // [rsp-Ch] [rbp-Ch] BYREF
  __int64 v2; // [rsp-8h] [rbp-8h]

  *(_QWORD *)&socketFD = sys_socket(2, 1, 0);
  v2 = 16777343;
  v1[1] = 16415;
  v1[0] = 2;
  return sys_connect(socketFD, (struct sockaddr *)v1, 16);
}
```

 ** ici,  j'ai eu une information assez capital qui m'a permis meme de comprendre generally le fonctionnement d'un botnet (J'avais recherché sur internet, mais pour ça démeurait toujours abstrait) :

### Une découverte de l'Adresse de Connexion**
- **v2 = 16777343** : En hexadécimal = `0x0100007F` = `127.0.0.1` (le localhost)
- **v1[1] = 16415** : Port en little-endian = `0x401F` = port 16415 

(Ah heureusement je sais que rien je ne serait cadeau et que je devrais toujours dealer avec les hex 😂💀)

**leçon tirée pour la suite** : Le malware se connecte à `127.0.0.1:16415`

à partir d'ici tout était devenu interressant et très informative, j'avais mon notebook à coté pour ne rien laisser...
---

## **ÉTAPE 5 : ANALYSE DU TRAITEMENT DES COMMANDES**

### **Fonction `IRC_PROCESS_READ()` - Le Cœur du Malware** 

<img width="625" height="355" alt="image" src="https://github.com/user-attachments/assets/62d6bc0d-fe17-4789-b58f-adff0bdb9e03" />

(Ceux qui on recherché sur ce type de botnet le savent déjà probablement)

Cette fonction est la plus intéressante car elle traite différents types de messages IRC (Internet Relay Chat) ici pour en savoir plus :

#### **Types de Commandes Supportées**
1. **PING** : Répond aux pings du serveur
2. **PASS** : Vérification d'un mot de passe
3. **EXEC** : Exécution de commandes système
4. **FLAG** : Affichage du flag chiffré

#### **Logique de Déchiffrement du Mot de Passe**
Partie qui nous interresse, 
```c

if ( (unsigned __int8)v18 >= 0x41u && (unsigned __int8)v18 <= 0x5Au )
{
  v18 += 19;  // ROT19 (C'etais une rotation, j'avoue que j'ai pas eu vite le reflexe 😂)
  if ( (unsigned __int8)v18 > 0x5Au )
    v18 = v18 - 90 + 64;  // Retour à 'A'
}
```

#### **Logique de Déchiffrement du Flag**
```c
//XOR avec le mot de passe déchiffré
for ( i = &IRC_PROCESS_FLAGTEXT; *i; ++i )
{
  *i ^= *v0++;  //XOR avec chaque caractère du mot de passe
  if ( ++v1 == IRC_PROCESS_PASS_LEN )
  {
    v0 = IRC_PROCESS_PASS_DEC;  //Recommence le mot de passe
    v1 = 0;
  }
}
```

---

##  **ÉTAPE 6 : EXTRACTION DES DONNÉES**

### **Recherche des Adresses Importantes pour les extraire ( ce que l'analyse des fonctions a revélé)**
En utilisant la fenêtre "Names", je trouve les adresses suivantes :

```
IRC_PROCESS_PASS = 0x40313C        //Mot de passe chiffré
IRC_PROCESS_FLAGTEXT = 0x4030D7    //Flag chiffré
IRC_PROCESS_PASS_LEN = 0x403145    //Longueur du mot de passe
IRC_PROCESS_PASSMSG = 0x40314D     //Message pour reconnaître PASS
IRC_PROCESS_FLAGMSG = 0x403116     //Message pour reconnaître FLAG
```
(Cette partie m'a pris du temps, c'etait vraiment manuel) 

et aussi les nom etaient un peu evident à mes yeux ex: je sais que LEN==Lenght,  MSG==Message, ...

### **Extraction des Données depuis la Vue Hex pour les 5 addresses**

En naviguant vers ces adresses dans la vue "Hex View-1" :

<img width="1210" height="721" alt="address" src="https://github.com/user-attachments/assets/4abee1d6-a635-4197-8a33-47defec1b7a1" />

#### **1-) Je trouve un now le mot passe : IRC_PROCESS_PASS (à Adresse 0x403130)**
```
4D 33 55 76 31 51 69 30 00
```
En ASCII : `M3Uv1Qi0` (8 caractères)

#### **2-) Flag Chiffré : IRC_PROCESS_FLAGTEXT (à l'adresse 0x4030D7)**
```
1C 67 00 0D 56 68 59 54 0B 03 73 12 6E 31 1B 53 0B 51 72 02 5F 6B 1D 4D 00
```
(25 octets de données chiffrées)

#### **3-)Longueur du Mot de Passe : IRC_PROCESS_PASS_LEN (à l'adresse 0x403145)**
```
08 00 00 00 00 00 00 00
```
Valeur : `8` (longueur du mot de passe)

---

##  **STEP 7 : DÉVELOPPEMENT DU SCRIPT DE DÉCHIFFREMENT**

Vue que chaque step etait important et décisive pour le dev du script, voici un overview de ce que j'ai noté:

### **Analyse de la Logique**

Le malware fonctionne finalement ainsi :
1. **Chiffre l'entrée utilisateur** avec ROT19
2. **Compare** avec le mot de passe stocké (qui est déjà déchiffré)
3. **Déchiffre le flag** avec XOR en utilisant le mot de passe déchiffré

### **Script Python de Déchiffrement (j'ai utilisé un env de python3.13 pour l"exécution)**

```python
#!/usr/bin/env python3

def rot19_decrypt(text):
    """Déchiffre un texte chiffré avec ROT19"""
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            decrypted = ord(char) - 19
            if decrypted < ord('A'):
                decrypted = decrypted + 26
            result += chr(decrypted)
        else:
            result += char
    return result

def xor_decrypt_flag(encrypted_flag, password):
    """Déchiffre le flag avec XOR"""
    decrypted = ""
    password_len = len(password)
    
    for i, byte in enumerate(encrypted_flag):
        if byte == 0:  
            continue
        password_char = password[i % password_len]
        decrypted_char = chr(byte ^ ord(password_char))
        decrypted += decrypted_char
    
    return decrypted

#Ici les données extraites du binaire 
IRC_PROCESS_PASS = "M3Uv1Qi0"
IRC_PROCESS_FLAGTEXT = [
    0x1C, 0x67, 0x00, 0x0D, 0x56, 0x68, 0x59, 0x54, 0x0B, 0x03,
    0x73, 0x12, 0x6E, 0x31, 0x1B, 0x53, 0x0B, 0x51, 0x72, 0x02,
    0x5F, 0x6B, 0x1D, 0x4D, 0x00
]

#et le déchiffrement
decrypted_password = rot19_decrypt(IRC_PROCESS_PASS)
decrypted_flag = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, decrypted_password)
print(f"Flag: HTB{{{decrypted_flag}}}")
```

---

## **STEP 8 : TESTS ET VALIDATION**


### **Premiers Tests**
```bash
python decrypt.py
# Résultat : HTB{ZTN{g"0dM0=d_{rcMb<tn!t}F}
```

what a hell ? 😂, Ok je dois je vois au moins un format qui saute à l'oeil , et c'est ici mon endurance a été multiplié  par 1000.

Remarque : Le flag ne semble pas correct. Je dois ajuster ma compréhension. 

### **Analyse Plus Approfondie**
En relisant le code du malware, je comprends que :
- Le mot de passe stocké `M3Uv1Qi0` est **déjà déchiffré**
- Le malware chiffre l'entrée utilisateur avec ROT19 pour la comparer
- Pour le flag, il faut utiliser le mot de passe déchiffré par ROT19

### **Alors voici la Correction du Script** (Bien qu'il y a d'autre outils pour le CHIFFREMENT/DECIFFREMENT ROT19, je préfère aller manuellement pour bien avoir de la main pour la prochaine fois)

```python
#Le mot de passe stocké est déjà déchiffré
#Je dois le chiffrer avec ROT19 pour obtenir la clé de déchiffrement

def rot19_encrypt(text):
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            encrypted = ord(char) + 19
            if encrypted > ord('Z'):
                encrypted = encrypted - 26
            result += chr(encrypted)
        else:
            result += char
    return result

#Test avec différentes combinaisons
encrypted_pass = rot19_encrypt("M3Uv1Qi0")  #==F3Nv1Ji0
decrypted_flag = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, encrypted_pass)
```

---

##  **STEP 9 : OBTENTION DU FLAG 😁**

### **Exécution du Script Final**
```bash
python decrypt_final.py
```


<img width="1242" height="677" alt="image" src="https://github.com/user-attachments/assets/b2896f82-433d-4c6a-b6ea-066db8a8f27d" />

**Résultat** :
```
Test 3: HT{g00d_01d_irc_b0tn3t}
```

Au debut j'ai copié et j'ai paste comme ça, et c'était wrong.

Mais bon relax, j'ai revu le format du flag, puis jack pot !!!

---


Le flag  : `HTB{g00d_01d_irc_b0tn3t}` 

## Fin.

Merci de m'avoir suivi jusqu'à la fin !!!
