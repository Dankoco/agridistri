const API_URL = 'http://localhost:3000/api';

async function chargerDonnees(url, callback, libelle) {
    try {
        const response = await fetch(url);
        const donnees = await response.json();
        callback(donnees);
    } catch (error) {
        console.error(`Erreur ${libelle}:`, error);
    }
}

function afficherMessage(messageElement, contenu, couleur, fond) {
    messageElement.style.background = fond;
    messageElement.style.color = couleur;
    messageElement.innerText = contenu;
    messageElement.classList.add('show');
}

async function fetchStocks() {
    await chargerDonnees(`${API_URL}/stocks`, (stocks) => {
        renderStocks(stocks);
        renderProductSelect(stocks);
    }, 'stocks');
}

async function fetchAgriculteurs() {
    await chargerDonnees(`${API_URL}/agriculteurs`, (agriculteurs) => {
        renderAgriculteurSelect(agriculteurs);
    }, 'agriculteurs');
}

async function fetchHistory() {
    await chargerDonnees(`${API_URL}/distributions`, (historique) => {
        renderHistory(historique);
    }, 'historique');
}

function renderStocks(stocks) {
    const grid = document.getElementById('stocks-grid');
    grid.innerHTML = stocks.map(stock => `
        <div class="card animate-fade-in">
            <div class="card-title">${stock.type}</div>
            <h3>${stock.nom}</h3>
            <div style="margin-top: 1rem;">
                <span class="stock-value">${stock.quantite}</span>
                <span class="stock-unit">${stock.unite}</span>
            </div>
            <div style="margin-top: 0.5rem; height: 4px; background: #eee; border-radius: 2px;">
                <div style="width: ${Math.min((stock.quantite / 1000) * 100, 100)}%; height: 100%; background: var(--primary); border-radius: 2px;"></div>
            </div>
        </div>
    `).join('');
}

function renderProductSelect(stocks) {
    const select = document.getElementById('produit');
    const valeurCourante = select.value;

    select.innerHTML = '<option value="">Sélectionner un produit</option>' +
        stocks.map(stock => `<option value="${stock.id}">${stock.nom} (Dispo: ${stock.quantite} ${stock.unite})</option>`).join('');

    select.value = valeurCourante;
}

function renderAgriculteurSelect(agriculteurs) {
    const select = document.getElementById('agriculteur');
    select.innerHTML = '<option value="">Sélectionner un agriculteur</option>' +
        agriculteurs.map(agriculteur => `<option value="${agriculteur.id}">${agriculteur.prenom} ${agriculteur.nom} - ${agriculteur.region}</option>`).join('');
}

function renderHistory(history) {
    const tbody = document.getElementById('history-body');
    tbody.innerHTML = history.map(item => `
        <tr>
            <td>${new Date(item.date).toLocaleDateString('fr-FR', { hour: '2-digit', minute: '2-digit' })}</td>
            <td><strong>${item.agriculteur_prenom} ${item.agriculteur_nom}</strong></td>
            <td>${item.stock_nom}</td>
            <td><span class="status-badge badge-warning">${item.quantite} ${item.unite}</span></td>
        </tr>
    `).join('');
}

const formulaireDistribution = document.getElementById('distribution-form');

formulaireDistribution.addEventListener('submit', async (e) => {
    e.preventDefault();

    const btn = document.getElementById('submit-btn');
    const message = document.getElementById('form-message');

    const data = {
        agriculteur_id: document.getElementById('agriculteur').value,
        stock_id: document.getElementById('produit').value,
        quantite: parseFloat(document.getElementById('quantite').value)
    };

    btn.disabled = true;
    btn.innerText = 'Traitement...';
    message.innerText = '';

    try {
        const response = await fetch(`${API_URL}/distribuer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            afficherMessage(message, '✅ ' + result.message, '#1e7e34', '#e6f4ea');
            formulaireDistribution.reset();
            fetchStocks();
            fetchHistory();
        } else {
            afficherMessage(message, '❌ ' + (result.error || 'Erreur inconnue'), '#d32f2f', '#ffebee');
        }
    } catch (error) {
        afficherMessage(message, '❌ Erreur de connexion au serveur', '#d32f2f', '#ffebee');
    } finally {
        btn.disabled = false;
        btn.innerText = 'Valider la Distribution';
    }
});

function init() {
    fetchStocks();
    fetchAgriculteurs();
    fetchHistory();
    setInterval(fetchStocks, 30000);
}

init();
