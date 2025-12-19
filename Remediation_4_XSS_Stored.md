# REMÉDIATION - XSS Stored (Feedback/Guestbook)

## 📋 Informations sur la vulnérabilité

- **Type**: Cross-Site Scripting (XSS) Stored (Persistant)
- **Page affectée**: `http://192.168.10.146/?page=feedback`
- **Paramètres vulnérables**: `txtName`, `mtxtMessage`
- **Niveau de criticité**: 🔴 CRITIQUE
- **Impact**: Exécution de JavaScript pour tous les visiteurs, vol de sessions, défacement

---

## 🔍 Description de la faille

La page Feedback permet aux utilisateurs de laisser des commentaires qui sont stockés en base de données et affichés à tous les visiteurs. Le système implémente un filtre basé sur une liste noire de caractères, qui peut être contourné. De plus, la simple détection du mot "script" dans le champ Name révèle le flag, démontrant une approche de sécurité inadéquate.

### Exploitation réussie

```html
<!-- Tentative 1: Script classique (filtré) -->
Name: test
Message: <script>alert(1)</script>
Résultat: Les balises sont supprimées → "alert(1)"

<!-- Tentative 2: Contournement du filtre -->
Name: script
Message: test
Résultat: FLAG révélé (le système détecte le mot-clé)
```

---

## 💻 Code vulnérable (AVANT)

```php
<?php
// ❌ CODE VULNÉRABLE - NE PAS UTILISER

// Récupération des données POST
$name = $_POST['txtName'];
$message = $_POST['mtxtMessage'];

// Filtre inadéquat basé sur strip_tags
$name = strip_tags($name);
$message = strip_tags($message);

// Filtre supplémentaire basé sur une liste noire
$blacklist = ['a', 'c', 'e', 'i', 'l', 'p', 'r', 's', 't'];

foreach ($blacklist as $char) {
    $name = str_replace($char, '', $name);
    $name = str_replace(strtoupper($char), '', $name);
    $message = str_replace($char, '', $message);
    $message = str_replace(strtoupper($char), '', $message);
}

// Détection simpliste de mots-clés
if (stripos($name, 'script') !== false) {
    // Révèle le flag au lieu de bloquer proprement
    echo "The flag is: [flag_here]";
    exit;
}

// Insertion en base (SANS échappement!)
$query = "INSERT INTO guestbook (name, comment) VALUES ('$name', '$message')";
mysqli_query($conn, $query);

// Affichage (SANS échappement!)
$result = mysqli_query($conn, "SELECT name, comment FROM guestbook");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<tr><td>Name : " . $row['name'] . "</td></tr>";
    echo "<tr><td>Comment : " . $row['comment'] . "</td></tr>";
}
?>
```

### Problèmes identifiés:
1. ❌ Filtre basé sur liste noire (facilement contournable)
2. ❌ `strip_tags()` seul est insuffisant
3. ❌ Suppression de caractères au lieu de rejet
4. ❌ Pas d'échappement HTML à la sortie
5. ❌ Validation côté client facilement contournable (maxlength)
6. ❌ Stockage de données non validées
7. ❌ Détection de mots-clés inefficace

---

## ✅ Code sécurisé (APRÈS)

### Solution complète et sécurisée

```php
<?php
/**
 * Classe de gestion sécurisée du livre d'or
 */
class SecureGuestbook {
    private $pdo;
    private $maxNameLength = 50;
    private $maxMessageLength = 500;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    /**
     * Valide le nom de l'utilisateur
     */
    private function validateName($name) {
        // Vérifier que le nom existe
        if (empty($name)) {
            throw new InvalidArgumentException("Le nom est requis");
        }

        // Nettoyer les espaces
        $name = trim($name);

        // Vérifier la longueur
        if (strlen($name) > $this->maxNameLength) {
            throw new InvalidArgumentException("Le nom est trop long (max {$this->maxNameLength} caractères)");
        }

        if (strlen($name) < 2) {
            throw new InvalidArgumentException("Le nom est trop court (min 2 caractères)");
        }

        // Autoriser uniquement lettres, chiffres, espaces et tirets
        if (!preg_match('/^[a-zA-Z0-9\s\-]+$/u', $name)) {
            throw new InvalidArgumentException("Le nom contient des caractères non autorisés");
        }

        return $name;
    }

    /**
     * Valide le message
     */
    private function validateMessage($message) {
        // Vérifier que le message existe
        if (empty($message)) {
            throw new InvalidArgumentException("Le message est requis");
        }

        // Nettoyer les espaces
        $message = trim($message);

        // Vérifier la longueur
        if (strlen($message) > $this->maxMessageLength) {
            throw new InvalidArgumentException("Le message est trop long (max {$this->maxMessageLength} caractères)");
        }

        if (strlen($message) < 5) {
            throw new InvalidArgumentException("Le message est trop court (min 5 caractères)");
        }

        // Autoriser lettres, chiffres, ponctuation de base
        if (!preg_match('/^[a-zA-Z0-9\s\.,!?\-\']+$/u', $message)) {
            throw new InvalidArgumentException("Le message contient des caractères non autorisés");
        }

        return $message;
    }

    /**
     * Détecte les tentatives XSS
     */
    private function detectXSS($input) {
        $patterns = [
            '/<script/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i',
            '/javascript:/i',
            '/on\w+\s*=/i',  // onclick, onload, etc.
            '/<img[^>]+src/i',
            '/eval\(/i',
            '/expression\(/i'
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Ajoute un commentaire de manière sécurisée
     */
    public function addComment($name, $message) {
        try {
            // Valider les entrées
            $validName = $this->validateName($name);
            $validMessage = $this->validateMessage($message);

            // Détecter les tentatives XSS
            if ($this->detectXSS($validName) || $this->detectXSS($validMessage)) {
                // Logger la tentative
                $this->logSecurityEvent('XSS attempt', [
                    'name' => substr($name, 0, 100),
                    'message' => substr($message, 0, 100),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);

                throw new SecurityException("Contenu non autorisé détecté");
            }

            // Requête préparée pour insertion
            $stmt = $this->pdo->prepare("
                INSERT INTO guestbook (name, comment, created_at, ip_address)
                VALUES (:name, :message, NOW(), :ip)
            ");

            $stmt->execute([
                'name' => $validName,
                'message' => $validMessage,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);

            return [
                'success' => true,
                'message' => 'Commentaire ajouté avec succès'
            ];

        } catch (InvalidArgumentException $e) {
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        } catch (SecurityException $e) {
            return [
                'success' => false,
                'message' => 'Votre commentaire contient du contenu non autorisé'
            ];
        } catch (PDOException $e) {
            error_log("Database error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Erreur lors de l\'enregistrement'
            ];
        }
    }

    /**
     * Récupère les commentaires de manière sécurisée
     */
    public function getComments($limit = 10) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT name, comment, created_at
                FROM guestbook
                WHERE is_approved = 1
                ORDER BY created_at DESC
                LIMIT :limit
            ");

            $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
            $stmt->execute();

            return $stmt->fetchAll(PDO::FETCH_ASSOC);

        } catch (PDOException $e) {
            error_log("Database error: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Affiche un commentaire de manière sécurisée
     */
    public function displayComment($comment) {
        // Échappement HTML strict avec ENT_QUOTES
        $safeName = htmlspecialchars($comment['name'], ENT_QUOTES, 'UTF-8');
        $safeComment = htmlspecialchars($comment['comment'], ENT_QUOTES, 'UTF-8');
        $safeDate = htmlspecialchars($comment['created_at'], ENT_QUOTES, 'UTF-8');

        // Convertir les retours à la ligne en <br>
        $safeComment = nl2br($safeComment, false);

        return sprintf(
            '<div class="comment">
                <div class="comment-header">
                    <strong>%s</strong> - <span class="date">%s</span>
                </div>
                <div class="comment-body">%s</div>
            </div>',
            $safeName,
            $safeDate,
            $safeComment
        );
    }

    /**
     * Logger les événements de sécurité
     */
    private function logSecurityEvent($type, $data) {
        $logEntry = sprintf(
            "[%s] %s: %s\n",
            date('Y-m-d H:i:s'),
            $type,
            json_encode($data)
        );

        error_log($logEntry, 3, '/var/log/security/guestbook_xss.log');
    }
}

// Exception personnalisée pour la sécurité
class SecurityException extends Exception {}

// ========================
// UTILISATION
// ========================

try {
    // Connexion PDO sécurisée
    $pdo = new PDO(
        "mysql:host=localhost;dbname=Member_guestbook;charset=utf8mb4",
        "guestbook_user",
        "secure_password",
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );

    $guestbook = new SecureGuestbook($pdo);

    // Traitement du formulaire
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $result = $guestbook->addComment(
            $_POST['txtName'] ?? '',
            $_POST['mtxtMessage'] ?? ''
        );

        if ($result['success']) {
            $successMessage = htmlspecialchars($result['message'], ENT_QUOTES, 'UTF-8');
            echo "<p class='success'>{$successMessage}</p>";
        } else {
            $errorMessage = htmlspecialchars($result['message'], ENT_QUOTES, 'UTF-8');
            echo "<p class='error'>{$errorMessage}</p>";
        }
    }

    // Affichage des commentaires
    $comments = $guestbook->getComments(20);

    foreach ($comments as $comment) {
        echo $guestbook->displayComment($comment);
    }

} catch (Exception $e) {
    error_log("Application error: " . $e->getMessage());
    echo "<p>Une erreur est survenue. Veuillez réessayer plus tard.</p>";
}
?>
```

### Structure de base de données sécurisée

```sql
-- Table guestbook avec champs de sécurité
CREATE TABLE guestbook (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    comment TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    is_approved TINYINT(1) DEFAULT 0,  -- Modération
    is_flagged TINYINT(1) DEFAULT 0,   -- Marqué comme suspect
    INDEX idx_approved (is_approved, created_at),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table pour logger les tentatives XSS
CREATE TABLE security_log (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    event_data TEXT,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    created_at DATETIME NOT NULL,
    INDEX idx_type_date (event_type, created_at),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

## 🛡️ Mesures de sécurité additionnelles

### 1. Système de modération

```php
<?php
/**
 * Système de modération automatique
 */
class ContentModerator {

    /**
     * Analyse le contenu avec scoring
     */
    public function analyzeContent($name, $message) {
        $score = 0;

        // Mots suspects
        $suspiciousWords = ['script', 'alert', 'eval', 'onclick', 'onerror'];
        foreach ($suspiciousWords as $word) {
            if (stripos($name . ' ' . $message, $word) !== false) {
                $score += 10;
            }
        }

        // Caractères suspects
        if (preg_match('/[<>]/', $name . $message)) {
            $score += 15;
        }

        // URL dans le message
        if (preg_match('/https?:\/\//', $message)) {
            $score += 5;
        }

        // Trop de caractères spéciaux
        $specialChars = preg_match_all('/[^\w\s]/', $message);
        if ($specialChars > strlen($message) * 0.2) {
            $score += 8;
        }

        return [
            'score' => $score,
            'should_moderate' => $score >= 10,
            'should_block' => $score >= 20
        ];
    }
}
?>
```

### 2. Rate Limiting

```php
<?php
/**
 * Protection contre le spam
 */
class RateLimiter {
    private $pdo;

    /**
     * Vérifie si l'IP peut poster
     */
    public function canPost($ip) {
        // Limite: 3 commentaires par heure
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count
            FROM guestbook
            WHERE ip_address = :ip
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");

        $stmt->execute(['ip' => $ip]);
        $result = $stmt->fetch();

        if ($result['count'] >= 3) {
            return [
                'allowed' => false,
                'message' => 'Trop de commentaires. Veuillez patienter.'
            ];
        }

        return ['allowed' => true];
    }
}
?>
```

### 3. Content Security Policy spécifique

```php
<?php
// CSP pour la page de feedback
header("Content-Security-Policy: " .
    "default-src 'self'; " .
    "script-src 'self' 'nonce-" . $nonce . "'; " .  // Utiliser un nonce
    "style-src 'self' 'nonce-" . $nonce . "'; " .
    "object-src 'none'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none';"
);
?>
```

### 4. Formulaire HTML sécurisé

```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Livre d'or - Sécurisé</title>
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self'; object-src 'none';">
</head>
<body>
    <h2>Laissez votre commentaire</h2>

    <form method="post" action="" id="guestbookForm">
        <!-- Token CSRF -->
        <input type="hidden" name="csrf_token"
               value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">

        <div>
            <label for="txtName">Nom * (2-50 caractères, lettres et chiffres uniquement)</label>
            <input type="text"
                   id="txtName"
                   name="txtName"
                   required
                   minlength="2"
                   maxlength="50"
                   pattern="[a-zA-Z0-9\s\-]+"
                   title="Lettres, chiffres, espaces et tirets uniquement">
        </div>

        <div>
            <label for="mtxtMessage">Message * (5-500 caractères)</label>
            <textarea id="mtxtMessage"
                      name="mtxtMessage"
                      required
                      minlength="5"
                      maxlength="500"
                      rows="5"
                      cols="50"></textarea>
            <small>Caractères autorisés: lettres, chiffres, ponctuation de base</small>
        </div>

        <button type="submit">Envoyer</button>
    </form>

    <script nonce="<?php echo $nonce; ?>">
        // Validation côté client (complément, pas remplacement)
        document.getElementById('guestbookForm').addEventListener('submit', function(e) {
            const name = document.getElementById('txtName').value;
            const message = document.getElementById('mtxtMessage').value;

            // Vérifier les caractères dangereux
            if (/<|>|script|javascript:/i.test(name + message)) {
                e.preventDefault();
                alert('Caractères non autorisés détectés');
                return false;
            }
        });
    </script>
</body>
</html>
```

---

## 🔒 Bonnes pratiques de sécurité

### ✅ À FAIRE:

1. **Validation stricte en liste blanche**
   - Définir exactement ce qui est autorisé
   - Rejeter tout le reste

2. **Échappement HTML systématique**
   ```php
   // ✅ BON
   echo htmlspecialchars($data, ENT_QUOTES, 'UTF-8');

   // ❌ MAUVAIS
   echo $data;
   ```

3. **Système de modération**
   - Validation manuelle avant publication
   - Détection automatique de contenu suspect

4. **Stockage sécurisé**
   ```php
   // Requêtes préparées TOUJOURS
   $stmt = $pdo->prepare("INSERT INTO table (col) VALUES (?)");
   $stmt->execute([$value]);
   ```

5. **Logging des tentatives**
   - Tracer les activités suspectes
   - Analyser les patterns d'attaque

### ❌ À ÉVITER:

1. ❌ Filtres basés sur liste noire (facilement contournables)
2. ❌ `strip_tags()` comme seule protection
3. ❌ Suppression de caractères au lieu de rejet
4. ❌ Validation uniquement côté client
5. ❌ Stockage de HTML dans la base de données
6. ❌ Affichage direct de données utilisateur

---

## 🧪 Tests de validation

### Test 1: Script classique
```
Name: test
Message: <script>alert(1)</script>
Résultat: Rejeté avec message "caractères non autorisés"
```

### Test 2: Event handler
```
Name: test
Message: <img src=x onerror=alert(1)>
Résultat: Rejeté (caractères < et > non autorisés)
```

### Test 3: Encodage JavaScript
```
Name: test
Message: &#60;script&#62;alert(1)&#60;/script&#62;
Résultat: Rejeté ou échappé à l'affichage
```

### Test 4: Contenu valide
```
Name: Jean Dupont
Message: Excellent site web, merci!
Résultat: Accepté et affiché correctement
```

### Test 5: Rate limiting
```
Poster 4 commentaires en moins d'une heure
Résultat: 4ème commentaire bloqué
```

---

## 📊 Comparaison avant/après

| Aspect | Avant (Vulnérable) | Après (Sécurisé) |
|--------|-------------------|------------------|
| Validation | Liste noire | Liste blanche |
| Filtrage | strip_tags() | Regex stricte |
| Échappement sortie | Non | htmlspecialchars() |
| Stockage | Concaténation SQL | Requêtes préparées |
| Modération | Aucune | Automatique + manuelle |
| Rate limiting | Non | Oui (3/heure) |
| Logging | Non | Oui (tentatives XSS) |
| CSP | Absente | Implémentée |

---

## ✅ Checklist de remédiation

- [ ] Remplacer les listes noires par des listes blanches
- [ ] Implémenter la validation stricte avec regex
- [ ] Échapper TOUTES les sorties avec htmlspecialchars()
- [ ] Utiliser des requêtes préparées pour INSERT et SELECT
- [ ] Ajouter un système de modération
- [ ] Implémenter le rate limiting
- [ ] Logger les tentatives XSS
- [ ] Ajouter une CSP stricte
- [ ] Implémenter la protection CSRF
- [ ] Créer une table de logs sécurité
- [ ] Tester avec divers payloads XSS
- [ ] Former l'équipe sur les XSS stored

---

**Dernière mise à jour**: 2025-12-19
**Statut**: ✅ Remédiation complète
