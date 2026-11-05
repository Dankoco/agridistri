#!/usr/bin/env python3
"""
Test script for phone number and ID document validation.
"""
import os
import requests
import json

from database import DB_PATH, init_db

# Réinitialiser la base pour éviter les doublons entre les exécutions
if os.path.exists(DB_PATH):
    try:
        os.remove(DB_PATH)
    except PermissionError:
        pass
init_db()

API_URL = "http://localhost:3000/api"

# Test data
# Chaque cas utilise un contact unique, et les numéros d'identité correspondent à la longueur attendue
# pour le type de pièce sélectionné.
# (nom, prenom, region, contact, numero_identite, type_piece, should_pass, description)
# Le cas de doublon est volontairement reproduit après un enregistrement valide.

test_cases = [
    ("Diallo", "Amadou", "Dakar", "771234567", "1751199000123", "CNI", True, "Valid Senegalese phone"),
    ("Sow", "Rama", "Thiès", "761234567", "123456789", "Passeport", True, "Valid passport - 9 digits"),
    ("Ba", "Moussa", "Kaolack", "751234567", "123456789012", "Carte de séjour", True, "Valid residence card - 12 digits"),
    ("Sy", "Fatou", "Ziguinchor", "701234567", "12345678", "Permis de conduire", True, "Valid driver licence - 8 digits"),
    ("Ndiaye", "Aïssatou", "Saint-Louis", "681234567", "1751199000127", "CNI", True, "Valid phone 68"),
    ("Diouf", "Moussa", "Dakar", "711234567", "1751199000133", "CNI", True, "Valid phone starting with 71"),
    ("Sarr", "Ousmane", "Diourbel", "771234567", "1751199000128", "CNI", False, "Invalid - duplicate number"),
    ("Ciss", "Mariama", "Kaolack", "771234568", "175119900012", "CNI", False, "Invalid ID - too short"),
    ("Ndiaye", "Papa", "Dakar", "771234569", "17511990001234", "CNI", False, "Invalid ID - too long"),
    ("Seide", "Khady", "Thiès", "821234567", "1751199000129", "CNI", False, "Invalid phone - starts with 8"),
    ("Mbow", "Aminata", "Dakar", "771234570", "123456789", "Passeport", True, "Valid passport - 9 digits"),
    ("Diop", "Ibrahima", "Kaolack", "771234571", "123456789012", "Carte de séjour", True, "Valid residence card - 12 digits"),
    ("Boum", "Awa", "Kaolack", "771234574", "123 456 789 012", "Carte de séjour", True, "Valid residence card - formatted with spaces"),
    ("Ndiaye", "Aminata", "Dakar", "+221 76 123 4578", "123456789", "Passeport", True, "Valid passport - international prefix"),
    ("Mendy", "Sali", "Thiès", "77-123-4578", "123456789012", "Carte de séjour", True, "Valid residence card - separated digits"),
    ("Gueye", "Ousmane", "Thiès", "771234572", "123456789", "CNI", False, "Invalid CNI - wrong length for CNI"),
    ("Fall", "Seydou", "Dakar", "771234573", "1751199000130", "Autre", False, "Invalid document type"),
]

print("=" * 70)
print("Testing Phone and ID Document Validation")
print("=" * 70)

passed = 0
failed = 0

for nom, prenom, region, contact, numero_identite, type_piece, should_pass, description in test_cases:
    data = {
        "nom": nom,
        "prenom": prenom,
        "region": region,
        "contact": contact,
        "numero_identite": numero_identite,
        "type_piece": type_piece
    }
    
    try:
        response = requests.post(f"{API_URL}/register-beneficiaire", json=data)
        success = response.status_code == 201
        
        status = "PASS" if success == should_pass else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        
        print(f"\n[{status}] {description}")
        print(f"   Input: {contact} | {numero_identite} | {type_piece}")
        print(f"   Expected: {'Success' if should_pass else 'Error'} | Got: {response.status_code}")
        if not success:
            result = response.json()
            if "error" in result:
                print(f"   Error: {result['error']}")
        
    except Exception as e:
        print(f"\n[ERROR] {description}")
        print(f"   Exception: {str(e)}")
        failed += 1

print("\n" + "=" * 70)
print(f"Results: {passed} passed, {failed} failed")
print("=" * 70)
