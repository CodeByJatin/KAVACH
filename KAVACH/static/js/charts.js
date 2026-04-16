// Global chart instances for destruction
let C_Ciphers = null;
let C_Tls = null;
let C_Keys = null;
let C_CAs = null;

const darkThemeColors = {
    ciphers: ['#3b82f6', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316'],
    tls: ['#10b981', '#f59e0b', '#ef4444', '#64748b'],
    keys: ['#6366f1', '#14b8a6', '#facc15', '#06b6d4'],
    cas: ['#ec4899', '#f43f5e', '#a855f7', '#6366f1']
};

const commonOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            position: 'right',
            labels: { color: '#cbd5e1', font: { family: 'Inter', size: 11 } }
        }
    }
};

window.renderCharts = function(data) {
    // Helper to destroy
    if(C_Ciphers) C_Ciphers.destroy();
    if(C_Tls) C_Tls.destroy();
    if(C_Keys) C_Keys.destroy();
    if(C_CAs) C_CAs.destroy();

    const ctxCiphers = document.getElementById('chartCiphers');
    const ctxTls = document.getElementById('chartTls');
    const ctxKeys = document.getElementById('chartKeys');
    const ctxCAs = document.getElementById('chartCAs');
    
    if(!ctxCiphers) return; // not on page

    // 1. Ciphers Donut
    C_Ciphers = new Chart(ctxCiphers, {
        type: 'doughnut',
        data: {
            labels: data.ciphers.labels,
            datasets: [{
                data: data.ciphers.data,
                backgroundColor: darkThemeColors.ciphers,
                borderWidth: 0, hoverOffset: 4
            }]
        },
        options: { ...commonOptions, cutout: '70%' }
    });

    // 2. TLS Bar
    C_Tls = new Chart(ctxTls, {
        type: 'bar',
        data: {
            labels: data.tls_versions.labels,
            datasets: [{
                label: 'Usage Count',
                data: data.tls_versions.data,
                backgroundColor: darkThemeColors.tls,
                borderRadius: 4
            }]
        },
        options: {
            ...commonOptions,
            plugins: { legend: { display: false } }, // override for bar
            scales: {
                y: { grid: { color: '#334155' }, ticks: { color: '#cbd5e1', stepSize: 1 } },
                x: { grid: { display: false }, ticks: { color: '#cbd5e1' } }
            }
        }
    });

    // 3. Keys Pie
    C_Keys = new Chart(ctxKeys, {
        type: 'pie',
        data: {
            labels: data.key_lengths.labels,
            datasets: [{
                data: data.key_lengths.data,
                backgroundColor: darkThemeColors.keys,
                borderWidth: 0, hoverOffset: 4
            }]
        },
        options: commonOptions
    });

    // 4. CAs PolarArea
    C_CAs = new Chart(ctxCAs, {
        type: 'polarArea',
        data: {
            labels: data.cas.labels,
            datasets: [{
                data: data.cas.data,
                backgroundColor: darkThemeColors.cas.map(c => c + '80'), // add opacity
                borderColor: darkThemeColors.cas,
                borderWidth: 1
            }]
        },
        options: {
            ...commonOptions,
            scales: {
                r: {
                    grid: { color: '#334155' },
                    ticks: { display: false }
                }
            }
        }
    });
};
