from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import check_password_hash
from datetime import timedelta
from functools import wraps
import sqlite3
import os
import re
import html
from dotenv import load_dotenv
from database import DB_PATH, init_db

load_dotenv()

# Configuration de l'application
app = Flask(__name__, static_url_path='', static_folder='.')

IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development').lower() == 'production'
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')

# CORS sécurisé : origines explicitement autorisées
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Headers de sécurité HTTP (CSP, HSTS, X-Frame-Options…)
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],  # inline scripts dans les HTML
    'style-src': ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
    'font-src': ["'self'", 'fonts.gstatic.com'],
    'img-src': ["'self'", 'data:'],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"],
}

Talisman(
    app,
    force_https=IS_PRODUCTION,           # Force HTTPS uniquement en production
    strict_transport_security=IS_PRODUCTION,
    session_cookie_secure=IS_PRODUCTION,
    content_security_policy=csp,
    referrer_policy='strict-origin-when-cross-origin',
    x_content_type_options=True,
    x_xss_protection=True,
    frame_options='DENY',
)

# JWT avec cookies HttpOnly (inaccessibles au JavaScript)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-key-change-in-production')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = IS_PRODUCTION        # True en prod (HTTPS requis)
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True           # Double Submit Cookie CSRF
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
    hours=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES_HOURS', 8))
)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(
    days=int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES_DAYS', 7))
)
jwt = JWTManager(app)

# Rate Limiting (protection brute-force)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "60 per minute"],
    storage_uri="memory://"
)

# Initialiser la base de données au lancement
init_db()


# Helpers base de données
def ouvrir_connexion():
    connexion = sqlite3.connect(DB_PATH)
    connexion.row_factory = sqlite3.Row
    # Activer les clés étrangères
    connexion.execute('PRAGMA foreign_keys = ON')
    return connexion


def charger_lignes(requete, parametres=()):
    connexion = ouvrir_connexion()
    try:
        lignes = connexion.execute(requete, parametres).fetchall()
        return [dict(ligne) for ligne in lignes]
    finally:
        connexion.close()


def charger_ligne(requete, parametres=()):
    connexion = ouvrir_connexion()
    try:
        ligne = connexion.execute(requete, parametres).fetchone()
        return dict(ligne) if ligne else None
    finally:
        connexion.close()


def executer_ecriture(requete, parametres=()):
    connexion = ouvrir_connexion()
    try:
        curseur = connexion.cursor()
        curseur.execute(requete, parametres)
        connexion.commit()
        return curseur.lastrowid
    finally:
        connexion.close()


# Journal d'audit
def audit_log(action, detail=None, user_id=None, username=None, status='SUCCESS'):
    """Enregistre une action sensible dans le journal d'audit."""
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ua = request.headers.get('User-Agent', '')[:255]
        executer_ecriture(
            '''INSERT INTO audit_logs (user_id, username, action, detail, ip_address, user_agent, status)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (user_id, username, action, detail, ip, ua, status)
        )
    except Exception:
        pass  # Ne jamais bloquer l'application à cause du logging


# Décorateurs d'autorisation par rôle
def admin_required(fn):
    """Décorateur : route réservée au rôle 'admin'."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'admin':
            audit_log('ACCES_REFUSE', f'Route admin: {request.path}',
                      user_id=claims.get('sub'), username=claims.get('username'),
                      status='DENIED')
            return jsonify({"error": "Accès refusé. Réservé aux administrateurs."}), 403
        return fn(*args, **kwargs)
    return wrapper


def distributeur_required(fn):
    """Décorateur : route réservée aux rôles 'distributeur' et 'admin'."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') not in ('distributeur', 'admin'):
            audit_log('ACCES_REFUSE', f'Route distributeur: {request.path}',
                      user_id=claims.get('sub'), username=claims.get('username'),
                      status='DENIED')
            return jsonify({"error": "Accès refusé. Authentification requise."}), 403
        return fn(*args, **kwargs)
    return wrapper


# Validation et sanitisation des entrées
def sanitiser_texte(valeur, max_len=200):
    """Échappe le HTML et tronque pour éviter les injections XSS."""
    if valeur is None:
        return ''
    return html.escape(str(valeur).strip())[:max_len]


def log_stock_transaction(stock_id, quantite, action, distributeur_id=None):
    executer_ecriture(
        '''INSERT INTO stock_transactions (distributeur_id, stock_id, action, quantite)
           VALUES (?, ?, ?, ?)''',
        (distributeur_id, stock_id, action, quantite)
    )


def normaliser_telephone_senegal(contact):
    if contact is None:
        return ''
    sanitized_contact = str(contact).strip()
    sanitized_contact = re.sub(r'^(?:\+?221|00221)', '', sanitized_contact)
    sanitized_contact = re.sub(r'[^0-9]', '', sanitized_contact)
    return sanitized_contact


def valider_telephone_senegal(contact):
    pattern = r'^(7[015678]|68)\d{7}$'
    sanitized_contact = normaliser_telephone_senegal(contact)
    return re.match(pattern, sanitized_contact) is not None


def normaliser_numero_identite(numero):
    if numero is None:
        return ''
    return re.sub(r'[\s\-./]+', '', str(numero).strip())


PIECE_RULES = {
    'CNI': 13,
    'Passeport': 9,
    'Carte de séjour': 12,
    'Permis de conduire': 8,
    'Permis': 8,
}


def valider_type_piece(type_piece):
    return type_piece in PIECE_RULES


def valider_numero_identite(numero, type_piece=None):
    expected_length = PIECE_RULES.get(type_piece, 13)
    numero_str = normaliser_numero_identite(numero)
    return re.match(rf'^\d{{{expected_length}}}$', numero_str) is not None


def message_erreur_numero_identite(numero, type_piece):
    if not valider_type_piece(type_piece):
        return "Type de pièce invalide. Acceptés: CNI, Passeport, Carte de séjour, Permis de conduire, Permis"

    expected_length = PIECE_RULES[type_piece]
    numero_str = normaliser_numero_identite(numero)

    if not re.match(r'^\d+$', numero_str):
        return f"Le numéro de pièce doit contenir uniquement des chiffres pour {type_piece}."

    if len(numero_str) != expected_length:
        return f"Le numéro de pièce doit contenir {expected_length} chiffres pour {type_piece}."

    return None


COMMUNE_TO_ZONE = {
    'Dakar': 'Ouest', 'Pikine': 'Ouest', 'Guédiawaye': 'Ouest',
    'Rufisque': 'Ouest', 'Thiès': 'Ouest', 'Mbour': 'Ouest',
    'Kaolack': 'Ouest', 'Saint-Louis': 'Ouest', 'Louga': 'Ouest',
    'Diourbel': 'Ouest', 'Tambacounda': 'Est', 'Kedougou': 'Est',
    'Kolda': 'Est', 'Sédhiou': 'Est', 'Matam': 'Est'
}


def determiner_zone(region):
    if not region:
        return 'Ouest'
    region = str(region).strip()
    return COMMUNE_TO_ZONE.get(region, 'Ouest' if region in ('Ouest', 'Est') else 'Ouest')


def assigner_distributeur_pour_zone(zone):
    distributeur = charger_ligne(
        "SELECT id FROM distributeurs WHERE role = 'distributeur' AND region = ?",
        (zone,)
    )
    return distributeur['id'] if distributeur else None


def creer_demande(agriculteur_id, stock_id, quantite, region=None):
    zone = determiner_zone(region)
    distributeur_id = assigner_distributeur_pour_zone(zone)
    demande_id = executer_ecriture(
        '''INSERT INTO demandes (agriculteur_id, stock_id, quantite, statut, distributeur_id)
           VALUES (?, ?, ?, 'EN_ATTENTE', ?)''',
        (agriculteur_id, stock_id, quantite, distributeur_id)
    )
    return demande_id, distributeur_id


def ajuster_stock_distributeur(distributeur_id, stock_id, quantite, action):
    conn = ouvrir_connexion()
    try:
        cur = conn.cursor()

        stock_global = cur.execute('SELECT quantite FROM stocks WHERE id = ?', (stock_id,)).fetchone()
        if not stock_global:
            raise ValueError('Stock introuvable')

        cur.execute('''
            INSERT INTO distributeur_stocks (distributeur_id, stock_id, quantite, updated_at)
            SELECT ?, ?, s.quantite, CURRENT_TIMESTAMP
            FROM stocks s
            WHERE s.id = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM distributeur_stocks ds
                  WHERE ds.distributeur_id = ?
                    AND ds.stock_id = ?
              )
        ''', (distributeur_id, stock_id, stock_id, distributeur_id, stock_id))

        if action == 'add':
            cur.execute('''
                INSERT INTO distributeur_stocks (distributeur_id, stock_id, quantite, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(distributeur_id, stock_id)
                DO UPDATE SET quantite = quantite + excluded.quantite,
                              updated_at = CURRENT_TIMESTAMP
            ''', (distributeur_id, stock_id, quantite))
        elif action == 'remove':
            stock_distributeur = cur.execute('''
                SELECT quantite FROM distributeur_stocks
                WHERE distributeur_id = ? AND stock_id = ?
            ''', (distributeur_id, stock_id)).fetchone()

            if not stock_distributeur:
                raise ValueError('Stock distributeur introuvable')

            if stock_distributeur['quantite'] < quantite:
                raise ValueError('Stock insuffisant pour ce distributeur')

            cur.execute('''
                UPDATE distributeur_stocks
                SET quantite = quantite - ?, updated_at = CURRENT_TIMESTAMP
                WHERE distributeur_id = ? AND stock_id = ?
            ''', (quantite, distributeur_id, stock_id))
        else:
            raise ValueError('Action invalide')

        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# Callback JWT : message d'erreur personnalisé
@jwt.unauthorized_loader
def unauthorized_callback(reason):
    return jsonify({"error": "Authentification requise. Veuillez vous connecter.", "code": "NOT_AUTHENTICATED"}), 401


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Session expirée. Veuillez vous reconnecter.", "code": "TOKEN_EXPIRED"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"error": "Token invalide.", "code": "INVALID_TOKEN"}), 422


# ROUTES API

# ── 1. Connexion ──────────────────────────────
@app.route('/api/login-distributeur', methods=['POST'])
@limiter.limit("5 per 15 minutes", error_message="Trop de tentatives. Réessayez dans 15 minutes.")
def login():
    try:
        data = request.json
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Données invalides"}), 400

        # Validation longueur pour éviter les payloads géants
        username = str(data.get('username', ''))[:100]
        password = str(data.get('password', ''))[:200]

        if not username or not password:
            return jsonify({"error": "Identifiant et mot de passe requis"}), 400

        user = charger_ligne(
            'SELECT id, username, nom, region, role, password FROM distributeurs WHERE username = ?',
            (username,)
        )

        if user and check_password_hash(user['password'], password):
            # Créer les tokens JWT signés
            additional_claims = {
                "role": user['role'],
                "username": user['username'],
                "nom": user['nom'],
                "region": user['region'],
            }
            access_token = create_access_token(
                identity=str(user['id']),
                additional_claims=additional_claims
            )
            refresh_token = create_refresh_token(identity=str(user['id']))

            # Journal d'audit
            audit_log('LOGIN_SUCCESS', f"Connexion: {username}",
                      user_id=user['id'], username=username)

            # Retourner les infos publiques + set cookies HttpOnly
            user_safe = {k: v for k, v in user.items() if k != 'password'}
            response = jsonify({"success": True, "user": user_safe})
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            return response, 200

        # Échec de connexion → audit
        audit_log('LOGIN_FAILED', f"Tentative échouée: {username}",
                  username=username, status='FAILED')
        return jsonify({"error": "Identifiants incorrects"}), 401

    except Exception as e:
        return jsonify({"error": f"Erreur serveur: {str(e)}"}), 500


# ── 2. Vérifier l'utilisateur courant (remplace localStorage) ──
@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_current_user():
    claims = get_jwt()
    user_id = get_jwt_identity()
    user = charger_ligne(
        'SELECT id, username, nom, region, role FROM distributeurs WHERE id = ?',
        (user_id,)
    )
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    return jsonify(user)


# ── 3. Refresh Token ──────────────────────────
@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    claims = get_jwt()
    user = charger_ligne(
        'SELECT id, username, nom, region, role FROM distributeurs WHERE id = ?',
        (identity,)
    )
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    additional_claims = {
        "role": user['role'],
        "username": user['username'],
        "nom": user['nom'],
        "region": user['region'],
    }
    new_token = create_access_token(identity=identity, additional_claims=additional_claims)
    response = jsonify({"success": True})
    set_access_cookies(response, new_token)
    return response, 200


# ── 4. Déconnexion ────────────────────────────
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    claims = get_jwt()
    audit_log('LOGOUT', f"Déconnexion: {claims.get('username')}",
              user_id=get_jwt_identity(), username=claims.get('username'))
    response = jsonify({"message": "Déconnecté avec succès"})
    unset_jwt_cookies(response)
    return response, 200


# ── 5. Récupérer les stocks (public) ──────────
@app.route('/api/stocks', methods=['GET'])
def get_stocks():
    stocks = charger_lignes('SELECT * FROM stocks')
    return jsonify(stocks)


# ── 6. Vérifier un bénéficiaire (public) ──────
@app.route('/api/check-beneficiaire/<contact>', methods=['GET'])
@limiter.limit("30 per minute")
def check_beneficiaire(contact):
    normalized_contact = normaliser_telephone_senegal(contact)
    farmer = charger_ligne(
        'SELECT id, nom, prenom, region FROM agriculteurs WHERE contact = ?',
        (normalized_contact,)
    )
    if farmer:
        return jsonify(farmer)
    return jsonify({"message": "Non trouvé"}), 404


# ── 7. Enregistrer un bénéficiaire (public) ───
@app.route('/api/register-beneficiaire', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.json
    contact = normaliser_telephone_senegal(data.get('contact'))
    numero_identite = normaliser_numero_identite(data.get('numero_identite'))
    nom = sanitiser_texte(data.get('nom'))
    prenom = sanitiser_texte(data.get('prenom'))
    region = sanitiser_texte(data.get('region'))

    if not valider_telephone_senegal(contact):
        return jsonify({"error": "Numéro de téléphone invalide. Format sénégalais requis (7XXXXXXXX)"}), 400

    if not valider_type_piece(data.get('type_piece')):
        return jsonify({"error": "Type de pièce invalide. Acceptés: CNI, Passeport, Carte de séjour, Permis de conduire, Permis"}), 400

    numero_identite_error = message_erreur_numero_identite(numero_identite, data.get('type_piece'))
    if numero_identite_error:
        return jsonify({"error": numero_identite_error}), 400

    try:
        new_id = executer_ecriture(
            '''INSERT INTO agriculteurs (nom, prenom, region, contact, numero_identite, type_piece)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (nom, prenom, region, contact, numero_identite, data['type_piece'])
        )
        return jsonify({"message": "Enregistré", "id": new_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Contact déjà existant"}), 400


# ── 8. Soumettre une demande (public) ─────────
@app.route('/api/demande', methods=['POST'])
@limiter.limit("20 per minute")
def submit_demande():
    data = request.json
    agriculteur = charger_ligne(
        'SELECT id, region FROM agriculteurs WHERE id = ?',
        (data['agriculteur_id'],)
    )
    if not agriculteur:
        return jsonify({"error": "Agriculteur non trouvé"}), 404

    creer_demande(
        agriculteur['id'],
        data['stock_id'],
        data['quantite'],
        agriculteur['region']
    )
    return jsonify({"message": "Demande enregistrée"})


# ── 9. Distribuer (authentifié) ───────────────
@app.route('/api/distribuer', methods=['POST'])
@distributeur_required
def distribuer():
    try:
        claims = get_jwt()
        data = request.json
        conn = ouvrir_connexion()
        cur = conn.cursor()

        stock = conn.execute(
            'SELECT quantite FROM stocks WHERE id = ?', (data['stock_id'],)
        ).fetchone()
        if not stock or stock['quantite'] < float(data['quantite']):
            conn.close()
            return jsonify({"error": "Stock insuffisant"}), 400

        cur.execute('UPDATE stocks SET quantite = quantite - ? WHERE id = ?',
                    (data['quantite'], data['stock_id']))

        distributeur_id = data.get('distributeur_id')
        if distributeur_id:
            ajuster_stock_distributeur(distributeur_id, data['stock_id'], data['quantite'], 'remove')

        cur.execute(
            'INSERT INTO distributions (agriculteur_id, stock_id, quantite) VALUES (?, ?, ?)',
            (data['agriculteur_id'], data['stock_id'], data['quantite'])
        )
        conn.commit()
        conn.close()

        audit_log('DISTRIBUTION', f"Stock {data['stock_id']}: -{data['quantite']} → agriculteur {data['agriculteur_id']}",
                  user_id=get_jwt_identity(), username=claims.get('username'))
        return jsonify({"message": "Distribution validée"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 10. Récupérer les agriculteurs (admin) ────
@app.route('/api/agriculteurs', methods=['GET'])
@admin_required
def get_agriculteurs():
    agriculteurs = charger_lignes('SELECT id, nom, prenom, region, contact FROM agriculteurs')
    return jsonify(agriculteurs)


# ── 11. Historique des distributions (admin) ──
@app.route('/api/distributions', methods=['GET'])
@admin_required
def get_distributions():
    distributions = charger_lignes('''
        SELECT d.id, d.date, a.nom as agriculteur_nom, a.prenom as agriculteur_prenom,
               s.nom as stock_nom, d.quantite, s.unite
        FROM distributions d
        JOIN agriculteurs a ON d.agriculteur_id = a.id
        JOIN stocks s ON d.stock_id = s.id
        ORDER BY d.date DESC
    ''')
    return jsonify(distributions)


# ── 12. Soumettre une demande bénéficiaire (public) ──
@app.route('/api/demandes-beneficiaire', methods=['POST'])
@limiter.limit("10 per minute")
def submit_beneficiaire_demande():
    try:
        data = request.json
        contact = normaliser_telephone_senegal(data.get('contact'))
        numero_identite = normaliser_numero_identite(data.get('numero_identite'))
        nom = sanitiser_texte(data.get('nom'))
        prenom = sanitiser_texte(data.get('prenom'))
        region = sanitiser_texte(data.get('region'))

        if not valider_telephone_senegal(contact):
            return jsonify({"error": "Numéro de téléphone invalide. Format sénégalais requis (7XXXXXXXX)"}), 400

        if not valider_type_piece(data.get('type_piece')):
            return jsonify({"error": "Type de pièce invalide. Acceptés: CNI, Passeport, Carte de séjour, Permis de conduire, Permis"}), 400

        numero_identite_error = message_erreur_numero_identite(numero_identite, data.get('type_piece'))
        if numero_identite_error:
            return jsonify({"error": numero_identite_error}), 400

        agriculteur = charger_ligne(
            'SELECT id, region FROM agriculteurs WHERE contact = ?', (contact,)
        )

        if agriculteur:
            agriculteur_id = agriculteur['id']
        else:
            agriculteur_id = executer_ecriture(
                '''INSERT INTO agriculteurs (nom, prenom, region, contact, numero_identite, type_piece)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (nom, prenom, region, contact, numero_identite, data['type_piece'])
            )
            agriculteur = {'region': region}

        stock = charger_ligne('SELECT quantite, nom, unite FROM stocks WHERE id = ?', (data['stock_id'],))
        if not stock:
            return jsonify({"error": "Intrant introuvable"}), 404

        quantite_demandee = float(data.get('quantite', 0))
        if quantite_demandee <= 0:
            return jsonify({"error": "La quantité demandée doit être supérieure à zéro."}), 400

        if quantite_demandee > stock['quantite']:
            return jsonify({
                "error": f"Quantité demandée ({quantite_demandee} {stock['unite']}) supérieure au stock disponible ({stock['quantite']} {stock['unite']}) pour '{stock['nom']}'. Veuillez réduire la quantité."
            }), 400

        creer_demande(agriculteur_id, data['stock_id'], data['quantite'], agriculteur['region'])
        return jsonify({"message": "Demande soumise avec succès"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 13. Récupérer les demandes d'un bénéficiaire (public) ──
@app.route('/api/demandes-beneficiaire', methods=['GET'])
@limiter.limit("30 per minute")
def get_beneficiaire_demandes():
    try:
        contact = request.args.get('contact')
        demandes = charger_lignes('''
            SELECT d.id, d.statut, d.quantite, d.date_demande, d.date_validation,
                   s.nom as stock_nom, s.unite as stock_unite, dist.nom as distributeur_nom
            FROM demandes d
            JOIN stocks s ON d.stock_id = s.id
            LEFT JOIN distributeurs dist ON d.distributeur_id = dist.id
            WHERE d.agriculteur_id IN (SELECT id FROM agriculteurs WHERE contact = ?)
            ORDER BY d.date_demande DESC
        ''', (contact,))
        return jsonify(demandes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 14. Demandes pour un distributeur (authentifié) ──
@app.route('/api/demandes-distributeur', methods=['GET'])
@distributeur_required
def get_distributeur_demandes():
    try:
        claims = get_jwt()
        statut = request.args.get('statut', 'EN_ATTENTE')
        distributeur_id = request.args.get('distributeur_id')

        # Un distributeur ne peut voir que ses propres demandes (sauf admin)
        if claims.get('role') != 'admin':
            distributeur_id = get_jwt_identity()

        distributeur = charger_ligne(
            'SELECT id, region FROM distributeurs WHERE id = ?', (distributeur_id,)
        )
        if not distributeur:
            return jsonify({"error": "Distributeur non trouvé"}), 404

        demandes = charger_lignes('''
            SELECT d.id, d.statut, d.quantite, d.date_demande, d.date_validation,
                   a.nom, a.prenom, a.contact, a.region, a.numero_identite,
                   s.nom as stock_nom, s.unite as stock_unite
            FROM demandes d
            JOIN agriculteurs a ON d.agriculteur_id = a.id
            JOIN stocks s ON d.stock_id = s.id
            WHERE d.statut = ? AND d.distributeur_id = ?
            ORDER BY d.date_demande DESC
        ''', (statut, distributeur_id))
        return jsonify(demandes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 15. Valider une demande (distributeur) ────
@app.route('/api/demandes/<int:demande_id>/valider', methods=['POST'])
@distributeur_required
def valider_demande(demande_id):
    try:
        claims = get_jwt()
        data = request.json or {}
        conn = ouvrir_connexion()
        cur = conn.cursor()

        demande = cur.execute('''
            SELECT id, agriculteur_id, stock_id, quantite, statut, distributeur_id
            FROM demandes WHERE id = ?
        ''', (demande_id,)).fetchone()

        if not demande:
            conn.close()
            return jsonify({"error": "Demande non trouvée"}), 404

        if demande['statut'] == 'VALIDEE':
            conn.close()
            return jsonify({"message": "Demande déjà validée"})

        # Sécurité : un distributeur ne peut valider que ses propres demandes
        if claims.get('role') != 'admin':
            user_id = int(get_jwt_identity())
            if demande['distributeur_id'] != user_id:
                conn.close()
                audit_log('VALIDATION_REFUSED',
                          f"Distributeur {user_id} tente de valider demande {demande_id} d'un autre",
                          user_id=user_id, username=claims.get('username'), status='DENIED')
                return jsonify({"error": "Accès refusé. Cette demande ne vous appartient pas."}), 403

        distributeur_id = data.get('distributeur_id') or demande['distributeur_id']
        if distributeur_id is None:
            conn.close()
            return jsonify({"error": "Distributeur requis pour la validation"}), 400

        stock_distributeur = cur.execute('''
            SELECT quantite FROM distributeur_stocks
            WHERE distributeur_id = ? AND stock_id = ?
        ''', (distributeur_id, demande['stock_id'])).fetchone()

        if not stock_distributeur or stock_distributeur['quantite'] < demande['quantite']:
            conn.close()
            return jsonify({"error": "Stock insuffisant pour ce distributeur"}), 400

        cur.execute('''
            UPDATE distributeur_stocks
            SET quantite = quantite - ?, updated_at = CURRENT_TIMESTAMP
            WHERE distributeur_id = ? AND stock_id = ?
        ''', (demande['quantite'], distributeur_id, demande['stock_id']))

        cur.execute('''
            UPDATE stocks SET quantite = quantite - ? WHERE id = ?
        ''', (demande['quantite'], demande['stock_id']))

        cur.execute('''
            INSERT INTO distributions (agriculteur_id, stock_id, quantite)
            VALUES (?, ?, ?)
        ''', (demande['agriculteur_id'], demande['stock_id'], demande['quantite']))

        cur.execute('''UPDATE demandes
                      SET statut = 'VALIDEE', date_validation = CURRENT_TIMESTAMP,
                          distributeur_id = ?
                      WHERE id = ?''',
                   (distributeur_id, demande_id))
        conn.commit()
        conn.close()

        audit_log('DEMANDE_VALIDEE', f"Demande #{demande_id} validée",
                  user_id=get_jwt_identity(), username=claims.get('username'))
        return jsonify({"message": "Demande validée"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 16. Rejeter une demande (distributeur) ────
@app.route('/api/demandes/<int:demande_id>/rejeter', methods=['POST'])
@distributeur_required
def rejeter_demande(demande_id):
    try:
        claims = get_jwt()
        conn = ouvrir_connexion()
        cur = conn.cursor()

        demande = cur.execute(
            'SELECT id, distributeur_id, statut FROM demandes WHERE id = ?', (demande_id,)
        ).fetchone()

        if not demande:
            conn.close()
            return jsonify({"error": "Demande non trouvée"}), 404

        # Sécurité : un distributeur ne peut rejeter que ses propres demandes
        if claims.get('role') != 'admin':
            user_id = int(get_jwt_identity())
            if demande['distributeur_id'] != user_id:
                conn.close()
                return jsonify({"error": "Accès refusé. Cette demande ne vous appartient pas."}), 403

        cur.execute('''UPDATE demandes
                      SET statut = 'REJETEE', date_validation = CURRENT_TIMESTAMP
                      WHERE id = ?''',
                   (demande_id,))
        conn.commit()
        conn.close()

        audit_log('DEMANDE_REJETEE', f"Demande #{demande_id} rejetée",
                  user_id=get_jwt_identity(), username=claims.get('username'))
        return jsonify({"message": "Demande rejetée"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 17. Stocks d'un distributeur (authentifié) ──
@app.route('/api/distributeurs/<int:distributeur_id>/stocks', methods=['GET'])
@distributeur_required
def get_distributeur_stocks(distributeur_id):
    try:
        claims = get_jwt()
        # Un distributeur ne peut voir que son propre stock
        if claims.get('role') != 'admin':
            if str(distributeur_id) != get_jwt_identity():
                return jsonify({"error": "Accès refusé."}), 403

        distributeur = charger_ligne('SELECT id FROM distributeurs WHERE id = ?', (distributeur_id,))
        if not distributeur:
            return jsonify({"error": "Distributeur non trouvé"}), 404

        conn = ouvrir_connexion()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO distributeur_stocks (distributeur_id, stock_id, quantite, updated_at)
            SELECT ?, s.id, s.quantite, CURRENT_TIMESTAMP
            FROM stocks s
            WHERE NOT EXISTS (
                SELECT 1 FROM distributeur_stocks ds
                WHERE ds.distributeur_id = ? AND ds.stock_id = s.id
            )
        ''', (distributeur_id, distributeur_id))
        conn.commit()
        conn.close()

        stocks = charger_lignes('''
            SELECT s.id, s.nom, s.type, ds.quantite, s.unite
            FROM distributeur_stocks ds
            JOIN stocks s ON ds.stock_id = s.id
            WHERE ds.distributeur_id = ?
            ORDER BY s.nom
        ''', (distributeur_id,))
        return jsonify(stocks)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 18. Modifier stock distributeur (authentifié) ──
@app.route('/api/distributeurs/<int:distributeur_id>/stocks/<int:stock_id>/<action>', methods=['POST'])
@distributeur_required
def update_distributeur_stock(distributeur_id, stock_id, action):
    try:
        claims = get_jwt()
        if claims.get('role') != 'admin':
            if str(distributeur_id) != get_jwt_identity():
                return jsonify({"error": "Accès refusé."}), 403

        data = request.json
        quantite = float(data.get('quantite'))

        distributeur = charger_ligne('SELECT id FROM distributeurs WHERE id = ?', (distributeur_id,))
        if not distributeur:
            return jsonify({"error": "Distributeur non trouvé"}), 404

        ajuster_stock_distributeur(distributeur_id, stock_id, quantite, action)
        log_stock_transaction(stock_id, quantite, action, distributeur_id)

        audit_log('STOCK_UPDATE',
                  f"Stock {stock_id}: {action} {quantite} (distributeur {distributeur_id})",
                  user_id=get_jwt_identity(), username=claims.get('username'))
        return jsonify({"message": "Stock distributeur mis à jour"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 19. Modifier stock global (admin seulement) ──
@app.route('/api/stocks/<int:stock_id>/<action>', methods=['POST'])
@admin_required
def update_stock(stock_id, action):
    try:
        claims = get_jwt()
        data = request.json
        quantite = float(data.get('quantite'))
        conn = ouvrir_connexion()
        cur = conn.cursor()

        if action == 'add':
            cur.execute('UPDATE stocks SET quantite = quantite + ? WHERE id = ?',
                       (quantite, stock_id))
        elif action == 'remove':
            cur.execute('UPDATE stocks SET quantite = quantite - ? WHERE id = ?',
                       (quantite, stock_id))
        else:
            conn.close()
            return jsonify({"error": "Action de stock invalide"}), 400

        conn.commit()
        conn.close()
        log_stock_transaction(stock_id, quantite, action)

        audit_log('STOCK_GLOBAL_UPDATE',
                  f"Stock global {stock_id}: {action} {quantite}",
                  user_id=get_jwt_identity(), username=claims.get('username'))
        return jsonify({"message": "Stock mis à jour"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 20. Statistiques Admin ────────────────────
@app.route('/api/admin-stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        stats = {
            'total_demandes': charger_ligne('SELECT COUNT(*) as cnt FROM demandes')['cnt'],
            'attente': charger_ligne("SELECT COUNT(*) as cnt FROM demandes WHERE statut = 'EN_ATTENTE'")['cnt'],
            'validees': charger_ligne("SELECT COUNT(*) as cnt FROM demandes WHERE statut = 'VALIDEE'")['cnt'],
            'rejetees': charger_ligne("SELECT COUNT(*) as cnt FROM demandes WHERE statut = 'REJETEE'")['cnt'],
            'total_agriculteurs': charger_ligne('SELECT COUNT(*) as cnt FROM agriculteurs')['cnt'],
            'total_distributeurs': charger_ligne("SELECT COUNT(*) as cnt FROM distributeurs WHERE role = 'distributeur'")['cnt'],
            'entrees': charger_ligne("SELECT COUNT(*) as cnt FROM stock_transactions WHERE action = 'add'")['cnt'],
            'sorties': charger_ligne("SELECT COUNT(*) as cnt FROM demandes WHERE statut = 'VALIDEE'")['cnt'],
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 21. Toutes les demandes (admin) ───────────
@app.route('/api/admin-demandes', methods=['GET'])
@admin_required
def admin_demandes():
    try:
        demandes = charger_lignes('''
            SELECT d.id, d.statut, d.quantite, d.date_demande, d.date_validation,
                   a.nom, a.prenom, a.contact, a.region,
                   s.nom as stock_nom, s.unite as stock_unite,
                   dist.nom as distributeur_nom
            FROM demandes d
            JOIN agriculteurs a ON d.agriculteur_id = a.id
            JOIN stocks s ON d.stock_id = s.id
            LEFT JOIN distributeurs dist ON d.distributeur_id = dist.id
            ORDER BY d.date_demande DESC
        ''')
        return jsonify(demandes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 22. Distributeurs (admin) ─────────────────
@app.route('/api/admin-distributeurs', methods=['GET'])
@admin_required
def admin_distributeurs():
    try:
        distributeurs = charger_lignes('''
            SELECT d.id, d.username, d.nom, d.region, d.role, COUNT(dem.id) as demandes_traitees
            FROM distributeurs d
            LEFT JOIN demandes dem ON d.id = dem.distributeur_id AND dem.statut = 'VALIDEE'
            WHERE d.role = 'distributeur'
            GROUP BY d.id
        ''')
        return jsonify(distributeurs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 23. Journal d'audit (admin seulement) ─────
@app.route('/api/admin-audit-logs', methods=['GET'])
@admin_required
def admin_audit_logs():
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        logs = charger_lignes('''
            SELECT id, user_id, username, action, detail, ip_address, status, created_at
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Servir les fichiers statiques ─────────────
@app.route('/')
def home():
    return app.send_static_file('index.html')


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'
    port = int(os.environ.get('PORT', 3000))
    app.run(port=port, debug=debug_mode)
