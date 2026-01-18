document.addEventListener('DOMContentLoaded', function() {
    const canvasFlow = document.getElementById('networkFlowChart');
    console.log("Graphique initialisé avec :", networkLabels.length, "points");
    
    // --- 1. GRAPHIQUE DES FLUX (MODE TIMELINE INFINIE) ---
    if (canvasFlow && typeof networkLabels !== 'undefined') {
        const ctxFlow = canvasFlow.getContext('2d');
        
        const gradient = ctxFlow.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(0, 188, 212, 0.4)');
        gradient.addColorStop(1, 'rgba(0, 188, 212, 0)');

        networkFlowChart = new Chart(ctxFlow, {
            type: 'line',
            data: {
                labels: networkLabels, 
                datasets: [{
                    label: 'Volume (Mo)',
                    data: networkValues,
                    borderColor: '#00bcd4',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointBackgroundColor: '#00bcd4',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, // Important pour contrôler la largeur manuellement
                animation: { duration: 200 }, // Animation très courte pour la fluidité
                plugins: { 
                    legend: { display: false },
                    tooltip: { enabled: true }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { 
                            color: '#888', 
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 20
                        }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        ticks: { 
                            color: '#888',
                            callback: function(value) { return value + ' Mo'; }
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // --- 2. GRAPHIQUE DES ALERTES (DOUGHNUT) ---
    const canvasPie = document.getElementById('alertsPieChart');
    if (canvasPie) {
        new Chart(canvasPie, {
            type: 'doughnut',
            data: {
                labels: ['Critique', 'Elevé', 'Moyen', 'Faible'],
                datasets: [{
                    data: [12, 28, 45, 110],
                    backgroundColor: ['#e74c3c', '#f39c12', '#3498db', '#95a5a6'],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: { 
                maintainAspectRatio: false, 
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { color: '#ccc', usePointStyle: true, padding: 20 } 
                    } 
                },
                cutout: '70%'
            }
        });
    }

    // --- 3. ACTIONS TABLEAU ---
    const tableBody = document.getElementById('ip-table-body');
    if (tableBody) {
        tableBody.addEventListener('click', function(e) {
            if (e.target && e.target.classList.contains('btn-bloquer')) {
                const ip = e.target.closest('tr').cells[0].innerText;
                if(confirm(`Voulez-vous vraiment bloquer l'IP ${ip} ?`)) {
                    e.target.innerText = "Bloqué";
                    e.target.style.background = "#555";
                    e.target.disabled = true;
                }
            }
        });
    }
});