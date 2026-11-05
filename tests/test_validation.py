"""Tests de validation du téléphone et des pièces d'identité (route /api/register-beneficiaire).

Les tests utilisent une base SQLite temporaire : la vraie base n'est jamais touchée.
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_tmpdir = tempfile.mkdtemp()
os.environ['AGRIDISTRI_DB'] = os.path.join(_tmpdir, 'test.db')

import server  # noqa: E402


@pytest.fixture(scope='module')
def client():
    server.limiter.enabled = False
    server.app.config['TESTING'] = True
    return server.app.test_client()


def inscrire(client, contact, numero, type_piece):
    return client.post('/api/register-beneficiaire', json={
        'nom': 'Test',
        'prenom': 'Utilisateur',
        'region': 'Dakar',
        'contact': contact,
        'numero_identite': numero,
        'type_piece': type_piece,
    })


@pytest.mark.parametrize('contact, numero, type_piece', [
    ('771234567', '1234567890123', 'CNI'),
    ('761234567', '123456789', 'Passeport'),
    ('751234567', '123456789012', 'Carte de séjour'),
    ('701234567', '12345678', 'Permis de conduire'),
    ('681234567', '1234567890124', 'CNI'),
    ('711234567', '1234567890125', 'CNI'),
    ('771234571', '123 456 789 012', 'Carte de séjour'),
    ('+221 76 123 4578', '123456789', 'Passeport'),
    ('77-123-4579', '123456789012', 'Carte de séjour'),
])
def test_inscription_valide(client, contact, numero, type_piece):
    assert inscrire(client, contact, numero, type_piece).status_code == 201


@pytest.mark.parametrize('contact, numero, type_piece', [
    ('771234568', '123456789012', 'CNI'),
    ('771234569', '12345678901234', 'CNI'),
    ('821234567', '1234567890126', 'CNI'),
    ('771234572', '123456789', 'CNI'),
    ('771234573', '1234567890127', 'Autre'),
])
def test_inscription_invalide(client, contact, numero, type_piece):
    assert inscrire(client, contact, numero, type_piece).status_code == 400


def test_contact_en_double(client):
    assert inscrire(client, '781234567', '1234567890128', 'CNI').status_code == 201
    assert inscrire(client, '781234567', '1234567890129', 'CNI').status_code == 400
