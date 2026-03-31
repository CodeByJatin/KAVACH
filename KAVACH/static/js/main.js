let currentDomainId = null;
let currentSubdomains = [];
let scanPoller = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchUserData();
    fetchDomains().then(() => {
        loadPage('home');
    });

    document.getElementById('domainSelect').addEventListener('change', (e) => {
        const val = e.target.value;
        currentDomainId = val === 'none' ? null : parseInt(val);
        // Reload current page with new context
        const activePage = document.querySelector('.nav-link.active').getAttribute('data-page');
        if(activePage) loadPage(activePage);
    });
});

async function fetchUserData() {
    try {
        const res = await fetch('/me');
        if(res.ok) {
            const data = await res.json();
            document.getElementById('userNameDisplay').textContent = data.name;
        }
    } catch(e) { console.error(e); }
}

async function fetchDomains() {
    try {
        const res = await fetch('/api/my-domains');
        if(res.ok) {
            const domains = await res.json();
            const select = document.getElementById('domainSelect');
            // reset options except first
            while(select.options.length > 1) { select.remove(1); }
            
            domains.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = `${d.domain_name} (${d.status})`;
                if(currentDomainId === d.id) opt.selected = true;
                select.appendChild(opt);
            });
            
            if(!currentDomainId && domains.length > 0) {
                // optionally auto select latest
                // currentDomainId = domains[0].id;
                // select.value = currentDomainId;
            }
        }
    } catch(e) { console.error(e); }
}

async function loadPage(pageName) {
    // UI updates
    document.querySelectorAll('.nav-link').forEach(el => {
        el.classList.remove('active');
        el.classList.add('text-slate-300');
    });
    
    const activeLink = document.querySelector(`.nav-link[data-page="${pageName}"]`);
    if(activeLink) {
        activeLink.classList.add('active');
        activeLink.classList.remove('text-slate-300');
    }
    
    // update title
    const titles = {
        'home': 'Dashboard',
        'discovery': 'Discovery CT Logs',
        'cbom': 'Crypto BOM',
        'posture': 'PQC Posture Assessment',
        'rating': 'Cyber Security Rating',
        'add_domain': 'Add Domain',
        'reporting': 'Intelligence Reporting'
    };
    document.getElementById('pageTitle').textContent = titles[pageName] || 'Overview';

    try {
        const res = await fetch(`/pages/${pageName}`);
        if(res.ok) {
            const html = await res.text();
            document.getElementById('mainContent').innerHTML = html;
            
            // Re-bind charts or data
            if(pageName === 'home') initDashboard();
            if(pageName === 'cbom') initCBOM();
            if(pageName === 'posture') initPosture();
            if(pageName === 'rating') initRating();
            if(pageName === 'discovery') initDiscovery();
            
        } else {
            document.getElementById('mainContent').innerHTML = `<p class="text-red-500">Error loading page.</p>`;
        }
    } catch(e) {
        console.error(e);
    }
}

// ---- PAGE INIT FUNCTIONS ----

let dashboardChartType = null;
let dashboardChartRisk = null;
let dashboardMap = null;

async function initDashboard() {
    try {
        const url = currentDomainId ? `/api/dashboard?domain_id=${currentDomainId}` : '/api/dashboard';
        const res = await fetch(url);
        if(res.ok) {
            const data = await res.json();
            document.getElementById('statDomains').textContent = data.domains;
            document.getElementById('statAssets').textContent = data.total_assets;
            document.getElementById('statElite').textContent = data.elite_pqc;
            document.getElementById('statCritical').textContent = data.critical_risks;
            
            // Render Charts
            const ctxType = document.getElementById('chartTypeDist');
            const ctxRisk = document.getElementById('chartRiskDist');
            
            if(ctxType && ctxRisk) {
                if(dashboardChartType) dashboardChartType.destroy();
                if(dashboardChartRisk) dashboardChartRisk.destroy();
                
                dashboardChartType = new Chart(ctxType, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(data.asset_types),
                        datasets: [{
                            data: Object.values(data.asset_types),
                            backgroundColor: ['#3b82f6', '#10b981', '#6366f1', '#64748b'],
                            borderWidth: 0, hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false, cutout: '65%',
                        plugins: { legend: { position: 'right', labels: { color: '#cbd5e1', font: { family: 'Inter', size: 11 } } } }
                    }
                });
                
                dashboardChartRisk = new Chart(ctxRisk, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(data.risk_distribution),
                        datasets: [{
                            label: 'Assets',
                            data: Object.values(data.risk_distribution),
                            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#64748b'],
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            y: { grid: { color: '#334155' }, ticks: { color: '#cbd5e1', stepSize: 1, font: { family: 'Inter' } } },
                            x: { grid: { display: false }, ticks: { color: '#cbd5e1', font: { family: 'Inter' } } }
                        }
                    }
                });
            }
        }
    } catch(e) { console.error(e); }
    
    // Fetch posture data for map + mini-table
    try {
        const postureUrl = currentDomainId ? `/api/posture/${currentDomainId}` : '/api/posture';
        const postureRes = await fetch(postureUrl);
        if(postureRes.ok) {
            const assets = await postureRes.json();
            initDashboardMap(assets);
            renderDashMiniTable(assets);
        }
    } catch(e) { console.error(e); }
}

function initDashboardMap(assets) {
    const mapEl = document.getElementById('dashboardMap');
    if(!mapEl || typeof L === 'undefined') return;
    
    if(dashboardMap) { dashboardMap.remove(); dashboardMap = null; }
    
    dashboardMap = L.map('dashboardMap', {
        center: [20.5937, 78.9629],
        zoom: 4,
        zoomControl: true,
        attributionControl: false
    });
    
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18
    }).addTo(dashboardMap);
    
    // Plot real IPs using geolocated lat/lng from the database
    const seenIPs = new Set();
    let markerCount = 0;
    
    assets.forEach(asset => {
        const ip = asset.ip_address;
        const lat = asset.latitude;
        const lng = asset.longitude;
        if(!ip || !lat || !lng || seenIPs.has(ip)) return;
        seenIPs.add(ip);
        
        const scoreColor = asset.pqc_score > 700 ? '#22c55e' : asset.pqc_score >= 400 ? '#eab308' : '#ef4444';
        
        const marker = L.circleMarker([lat, lng], {
            radius: 6,
            fillColor: scoreColor,
            color: scoreColor,
            weight: 1,
            opacity: 0.9,
            fillOpacity: 0.7
        }).addTo(dashboardMap);
        
        const locationStr = [asset.city, asset.country].filter(Boolean).join(', ') || 'Unknown';
        
        marker.bindPopup(`
            <div style="font-family:Inter;font-size:12px;color:#1e293b;min-width:180px">
                <b>${asset.subdomain}</b><br>
                IP: <code>${ip}</code><br>
                Location: ${locationStr}<br>
                TLS: ${asset.tls_version || 'N/A'}<br>
                Score: <b>${asset.pqc_score || 0}</b>
            </div>
        `);
        markerCount++;
    });
    
    // Invalidate size after render (Leaflet needs this when container was hidden)
    setTimeout(() => { if(dashboardMap) dashboardMap.invalidateSize(); }, 200);
}

function renderDashMiniTable(assets) {
    const tbody = document.getElementById('dashMiniTableBody');
    if(!tbody) return;
    tbody.innerHTML = '';
    
    // Show top 10 assets
    const top = assets.slice(0, 10);
    
    top.forEach(item => {
        let badgeClass, badgeText;
        if(item.scan_error) {
            badgeClass = 'bg-red-500/20 text-red-400 border border-red-500/30';
            badgeText = 'Failed';
        } else if(item.pqc_score > 700) {
            badgeClass = 'bg-green-500/20 text-green-400 border border-green-500/30';
            badgeText = 'Elite';
        } else if(item.pqc_score >= 400) {
            badgeClass = 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
            badgeText = 'Standard';
        } else {
            badgeClass = 'bg-red-500/20 text-red-500 border border-red-500/30';
            badgeText = 'Legacy';
        }
        
        tbody.innerHTML += `
            <tr class="hover:bg-slate-800/50 transition-colors">
                <td class="px-6 py-3 font-medium text-white">${item.subdomain}</td>
                <td class="px-6 py-3 text-slate-400">${item.tls_version || '-'}</td>
                <td class="px-6 py-3 font-bold ${item.pqc_score > 700 ? 'text-green-400' : 'text-slate-300'}">${item.pqc_score || 0}</td>
                <td class="px-6 py-3"><span class="px-2 py-0.5 rounded text-xs font-medium ${badgeClass}">${badgeText}</span></td>
            </tr>
        `;
    });
    
    if(top.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500">No scanned assets yet. Add a domain and run a deep scan.</td></tr>';
    }
}

let currentPostureData = [];
let postureSortDesc = true;

async function initPosture() {
    try {
        const url = currentDomainId ? `/api/posture/${currentDomainId}` : '/api/posture';
        const res = await fetch(url);
        if(res.ok) {
            currentPostureData = await res.json();
            
            // Calculate Top Metrics
            let totalScore = 0;
            let eliteCount = 0;
            let criticalCount = 0;
            let validAssets = 0;
            
            currentPostureData.forEach(item => {
                if(!item.scan_error) {
                    totalScore += (item.pqc_score || 0);
                    validAssets++;
                    if(item.pqc_score > 700) eliteCount++;
                    if(item.pqc_score < 100) criticalCount++;
                } else {
                    criticalCount++;
                }
            });
            
            const avg = validAssets > 0 ? Math.round(totalScore / validAssets) : 0;
            document.getElementById('avgPostureScore').textContent = avg;
            document.getElementById('elitePostureCount').textContent = eliteCount;
            document.getElementById('criticalPostureCount').textContent = criticalCount;
            
            renderPostureTable(currentPostureData);
        }
    } catch(e) { console.error(e); }
}

function renderPostureTable(data) {
    const tbody = document.getElementById('postureTableBody');
    if(!tbody) return;
    tbody.innerHTML = '';
    
    data.forEach((item, idx) => {
        let badgeClass = 'bg-slate-700 text-slate-300';
        if(item.pqc_score > 700) badgeClass = 'bg-green-500/20 text-green-400 border border-green-500/30';
        else if(item.pqc_score >= 400) badgeClass = 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
        else if(item.pqc_score >= 100) badgeClass = 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
        else badgeClass = 'bg-red-500/20 text-red-500 border border-red-500/30';
        
        const stat = item.scan_error ? 'Failed' : item.pqc_status;
        const errHtml = item.scan_error ? `<br><span class="text-xs text-red-400">${item.scan_error}</span>` : '';
        
        // Escape data for inline JSON push
        const safeData = encodeURIComponent(JSON.stringify(item));
        
        tbody.innerHTML += `
            <tr class="hover:bg-slate-800/50 transition-colors">
                <td class="px-6 py-4 font-medium">${item.subdomain}</td>
                <td class="px-6 py-4 text-slate-400">${item.tls_version || '-'}</td>
                <td class="px-6 py-4 text-slate-400 text-xs font-mono break-all">${item.cipher_suite || '-'}</td>
                <td class="px-4 py-4 text-slate-400">${item.key_length || '-'}</td>
                <td class="px-4 py-4 font-bold ${item.pqc_score > 700 ? 'text-green-400' : 'text-slate-300'}">${item.pqc_score || 0}</td>
                <td class="px-6 py-4 text-center">
                    <button onclick="openPQCModal('${safeData}')" class="px-3 py-1 bg-slate-700 hover:bg-slate-600 border border-slate-500 text-white text-xs rounded transition-colors shadow-sm">
                        <i class="fas fa-search-plus mr-1 text-yellow-400"></i> Inspect
                    </button>
                    ${errHtml}
                </td>
            </tr>
        `;
    });
    
    if(data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">No assets found matching the filter.</td></tr>';
    }
}

window.filterPosture = function(level) {
    // update buttons UI
    ['all', 'elite', 'standard', 'legacy', 'critical'].forEach(t => {
        const el = document.getElementById(`flt-${t}`);
        if(el) el.className = "px-4 py-1.5 rounded-full text-sm font-medium text-slate-300 bg-slate-800/50 hover:bg-slate-700/50 transition-colors border border-slate-600";
    });
    
    const active = document.getElementById(`flt-${level}`);
    if(active) active.className = "px-4 py-1.5 rounded-full text-sm font-semibold text-rose-900 bg-yellow-500 shadow-sm transition-colors border border-yellow-400";
    
    let filtered = currentPostureData;
    if(level === 'elite') filtered = currentPostureData.filter(d => d.pqc_score > 700);
    else if(level === 'standard') filtered = currentPostureData.filter(d => d.pqc_score >= 400 && d.pqc_score <= 700);
    else if(level === 'legacy') filtered = currentPostureData.filter(d => d.pqc_score >= 100 && d.pqc_score < 400);
    else if(level === 'critical') filtered = currentPostureData.filter(d => d.pqc_score < 100 || d.scan_error);
    
    renderPostureTable(filtered);
}

window.sortPostureByScore = function() {
    postureSortDesc = !postureSortDesc;
    let sorted = [...currentPostureData].sort((a,b) => {
        const sa = a.pqc_score || 0;
        const sb = b.pqc_score || 0;
        return postureSortDesc ? sb - sa : sa - sb;
    });
    
    currentPostureData = sorted;
    
    // re-apply filter if any is active based on class
    let activeFlt = 'all';
    ['all', 'elite', 'standard', 'legacy', 'critical'].forEach(t => {
        const el = document.getElementById(`flt-${t}`);
        if(el && el.classList.contains('bg-yellow-500')) activeFlt = t;
    });
    
    window.filterPosture(activeFlt);
}

window.openPQCModal = function(safeDataStr) {
    const data = JSON.parse(decodeURIComponent(safeDataStr));
    
    document.getElementById('modalSubdomain').textContent = data.subdomain || 'Unknown';
    document.getElementById('modalCA').textContent = data.cert_authority || 'Unknown Provider';
    
    const elScoreBadge = document.getElementById('modalScoreBadge');
    elScoreBadge.textContent = data.pqc_score || 0;
    
    // Style Badge
    if(data.pqc_score > 700) elScoreBadge.className = "text-2xl font-black px-4 py-1 rounded bg-green-500/20 text-green-400 border border-green-500";
    else if(data.pqc_score >= 400) elScoreBadge.className = "text-2xl font-black px-4 py-1 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500";
    else if(data.pqc_score >= 100) elScoreBadge.className = "text-2xl font-black px-4 py-1 rounded bg-orange-500/20 text-orange-400 border border-orange-500";
    else elScoreBadge.className = "text-2xl font-black px-4 py-1 rounded bg-red-500/20 text-red-500 border border-red-500";
    
    const details = data.pqc_details || {};
    document.getElementById('modalTlsScore').textContent = `+${details.tls_score || 0} pts`;
    document.getElementById('modalCipherScore').textContent = `+${details.cipher_score || 0} pts`;
    document.getElementById('modalKeyScore').textContent = `+${details.key_score || 0} pts`;
    document.getElementById('modalPqcScore').textContent = `+${details.compliance_score || 0} pts`;
    
    document.getElementById('modalRecommendation').textContent = data.recommendation || 'No recommendation available (run scan).';

    // Show modal
    document.getElementById('pqcModal').classList.remove('hidden');
}

window.closePQCModal = function() {
    document.getElementById('pqcModal').classList.add('hidden');
}

async function initRating() {
    try {
        const url = currentDomainId ? `/api/rating/${currentDomainId}` : '/api/rating';
        const res = await fetch(url);
        if(res.ok) {
            const data = await res.json();
            document.getElementById('ratingScore').textContent = data.average_score;
            document.getElementById('ratingLabel').textContent = data.rating;
            
            // update ring (svg dash offset: 251.2 is 0%, 0 is 100%)
            const percent = data.average_score / 1000;
            const ring = document.getElementById('ratingRing');
            const glow = document.getElementById('ratingGlow');
            
            setTimeout(() => {
                ring.style.strokeDashoffset = 251.2 - (251.2 * percent);
                if(percent > 0.7) { ring.style.stroke = '#4ade80'; glow.className = glow.className.replace('blue', 'green'); }
                else if(percent >= 0.4) { ring.style.stroke = '#eab308'; glow.className = glow.className.replace('blue', 'yellow'); }
                else if(percent >= 0.1) { ring.style.stroke = '#f97316'; glow.className = glow.className.replace('blue', 'orange'); }
                else { ring.style.stroke = '#ef4444'; glow.className = glow.className.replace('blue', 'red'); }
            }, 100);
        }
    } catch(e) { console.error(e); }
}

let currentDiscoveryData = [];
let currentDiscoveryTab = 'domains';
let currentDiscoverySubTab = 'all';

async function initDiscovery() {
    try {
        const url = currentDomainId ? `/api/posture/${currentDomainId}` : '/api/posture';
        const res = await fetch(url);
        if(res.ok) {
            currentDiscoveryData = await res.json();
            
            // Re-calc counts roughly based on items
            document.getElementById('countDomains').textContent = `(${currentDiscoveryData.length})`;
            document.getElementById('countSSL').textContent = `(${currentDiscoveryData.length})`;
            document.getElementById('countIPs').textContent = `(${currentDiscoveryData.length})`;
            document.getElementById('countSoftware').textContent = `(${currentDiscoveryData.length})`;
            
            document.getElementById('countAll').textContent = `(${currentDiscoveryData.length})`;
            
            renderDiscoveryTable();
        }
    } catch(e) { console.error(e); }
}

window.switchDiscoveryTab = function(tab) {
    currentDiscoveryTab = tab;
    ['domains', 'ssl', 'ips', 'software'].forEach(t => {
        const el = document.getElementById(`tabBtn-${t}`);
        if(el) el.className = "flex-1 py-2 px-4 rounded-full text-sm font-semibold text-white hover:bg-white/10 transition-all text-center tracking-wide";
    });
    const active = document.getElementById(`tabBtn-${tab}`);
    if(active) active.className = "flex-1 py-2 px-4 rounded-full text-sm font-semibold text-rose-900 bg-yellow-500 shadow-sm transition-all text-center tracking-wide";
    renderDiscoveryTable();
}

window.switchDiscoverySubTab = function(subTab) {
    currentDiscoverySubTab = subTab;
    ['all', 'new', 'false_positive', 'confirmed'].forEach(t => {
        const el = document.getElementById(`subTabBtn-${t}`);
        if(el) el.className = "text-sm font-medium text-slate-400 hover:text-white pb-2 px-1 border-b-2 border-transparent hover:border-slate-500";
    });
    const active = document.getElementById(`subTabBtn-${subTab}`);
    if(active) active.className = "text-sm font-medium text-yellow-400 border-b-2 border-yellow-400 pb-2 px-1";
    renderDiscoveryTable();
}

function renderDiscoveryTable() {
    const thead = document.getElementById('discoveryTableHeader');
    const tbody = document.getElementById('discoveryTableBody');
    if(!thead || !tbody) return;
    
    thead.innerHTML = '';
    tbody.innerHTML = '';
    
    // Filtering logic based on subTab (simple mock)
    let displayData = currentDiscoveryData;
    if(currentDiscoverySubTab === 'confirmed') displayData = displayData.filter(d => d.pqc_score > 400);
    
    if (currentDiscoveryTab === 'domains') {
        thead.innerHTML = `
            <tr>
                <th class="px-6 py-4">Detection Date</th>
                <th class="px-6 py-4">Domain Name</th>
                <th class="px-6 py-4">Status</th>
            </tr>
        `;
        displayData.forEach(item => {
            let statHtml = item.pqc_score > 400 ? `<span class="px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 text-xs">Confirmed</span>` : `<span class="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-xs">New</span>`;
            let scanDateStr = item.scanned_at ? new Date(item.scanned_at).toLocaleDateString() : '-';
            tbody.innerHTML += `
                <tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-4 text-slate-400">${scanDateStr}</td>
                    <td class="px-6 py-4 font-medium text-white">${item.subdomain}</td>
                    <td class="px-6 py-4">${statHtml}</td>
                </tr>
            `;
        });
    } else if (currentDiscoveryTab === 'ssl') {
        thead.innerHTML = `
            <tr>
                <th class="px-6 py-4">Subdomain</th>
                <th class="px-6 py-4">TLS Version</th>
                <th class="px-6 py-4">Cipher Suite</th>
                <th class="px-6 py-4">Posture</th>
            </tr>
        `;
        displayData.forEach(item => {
            let statHtml = item.pqc_score > 700 ? `<span class="px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 text-xs">Elite</span>` : `<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-500 border border-red-500/30 text-xs">Legacy</span>`;
            tbody.innerHTML += `
                <tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-4 font-medium text-white">${item.subdomain}</td>
                    <td class="px-6 py-4 text-slate-400">${item.tls_version || '-'}</td>
                    <td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.cipher_suite || '-'}</td>
                    <td class="px-6 py-4">${statHtml}</td>
                </tr>
            `;
        });
    } else if (currentDiscoveryTab === 'ips') {
        thead.innerHTML = `
            <tr>
                <th class="px-6 py-4">Subdomain</th>
                <th class="px-6 py-4">Resolves To</th>
            </tr>
        `;
        displayData.forEach(item => {
            tbody.innerHTML += `
                <tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-4 font-medium text-white">${item.subdomain}</td>
                    <td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.ip_address || 'Unresolved'}</td>
                </tr>
            `;
        });
    } else if (currentDiscoveryTab === 'software') {
        thead.innerHTML = `
            <tr>
                <th class="px-6 py-4">Subdomain</th>
                <th class="px-6 py-4">Server Header</th>
                <th class="px-6 py-4">Risk Level</th>
            </tr>
        `;
        displayData.forEach(item => {
            let badge = `<span class="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 text-xs">Medium</span>`;
            if (item.pqc_score < 400) badge = `<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-xs">High</span>`;
            
            tbody.innerHTML += `
                <tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-4 font-medium text-white">${item.subdomain}</td>
                    <td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.server_software || 'Unknown'}</td>
                    <td class="px-6 py-4">${badge}</td>
                </tr>
            `;
        });
    }
    
    if(displayData.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500">No assets found for this filter.</td></tr>`;
    }
}

async function initCBOM() {
    try {
        const url = currentDomainId ? `/api/cbom/${currentDomainId}` : '/api/cbom';
        const res = await fetch(url);
        if(res.ok) {
            const data = await res.json();
            if(window.renderCharts) window.renderCharts(data); // charts.js
        }
    } catch(e) { console.error(e); }
}

// ---- DISCOVERY AND SCANNING ----

// Stores all scannable items (active + suspicious) with their original index
let allScannable = [];

async function startDiscovery(e) {
    e.preventDefault();
    const domain = document.getElementById('domainInput').value;
    const btn = document.getElementById('btnDiscover');
    const loading = document.getElementById('loadingStatus1');
    
    btn.disabled = true;
    loading.classList.remove('hidden');
    
    try {
        const res = await fetch('/api/discover', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        
        if(res.ok) {
            const data = await res.json();
            currentDomainId = data.domain_id;
            
            await fetchDomains();
            document.getElementById('domainSelect').value = currentDomainId;
            
            const counts = data.counts || {};
            
            // Show summary stats
            document.getElementById('discovery-summary').classList.remove('hidden');
            document.getElementById('countActive').textContent = counts.active || 0;
            document.getElementById('countSuspicious').textContent = counts.suspicious || 0;
            document.getElementById('countUnresolvable').textContent = counts.unresolvable || 0;
            document.getElementById('countExternal').textContent = counts.external || 0;
            
            // Build scannable array: active first, then suspicious
            allScannable = [];
            const activeList = data.active || [];
            const suspiciousList = data.suspicious || [];
            const unresolvableList = data.unresolvable || [];
            const externalList = data.external || [];
            
            activeList.forEach(s => { s._group = 'active'; allScannable.push(s); });
            suspiciousList.forEach(s => { s._group = 'suspicious'; allScannable.push(s); });
            
            // currentSubdomains = all scannable for deep scan reference
            currentSubdomains = allScannable;
            
            // Show step 2
            document.getElementById('step2-container').classList.remove('hidden');
            
            // Render ACTIVE table
            const activeTbody = document.getElementById('activeTableBody');
            activeTbody.innerHTML = '';
            activeList.forEach((sub, _) => {
                const globalIdx = allScannable.indexOf(sub);
                const isMain = sub.subdomain === domain;
                const badge = isMain ? '<span class="ml-2 text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">APEX</span>' : '';
                const rowBg = isMain ? 'bg-blue-900/20' : '';
                
                activeTbody.innerHTML += `
                    <tr class="${rowBg} hover:bg-slate-800/80 transition-colors">
                        <td class="px-3 py-2">
                            <input type="checkbox" onchange="updateSelectedCount()" class="sub-checkbox w-4 h-4 text-green-600 bg-slate-700 border-slate-500 rounded cursor-pointer" data-group="active" value="${globalIdx}">
                        </td>
                        <td class="px-3 py-2 font-medium text-sm">${sub.subdomain}${badge}</td>
                        <td class="px-3 py-2 font-mono text-xs text-slate-400">${sub.ip_address || '-'}</td>
                        <td class="px-3 py-2 text-slate-400 text-xs">${sub.server_software || '-'}</td>
                    </tr>
                `;
            });
            
            // Render SUSPICIOUS table
            if(suspiciousList.length > 0) {
                document.getElementById('section-suspicious').classList.remove('hidden');
                const suspTbody = document.getElementById('suspiciousTableBody');
                suspTbody.innerHTML = '';
                suspiciousList.forEach((sub, _) => {
                    const globalIdx = allScannable.indexOf(sub);
                    suspTbody.innerHTML += `
                        <tr class="hover:bg-yellow-900/10 transition-colors">
                            <td class="px-3 py-2">
                                <input type="checkbox" onchange="updateSelectedCount()" class="sub-checkbox w-4 h-4 text-yellow-600 bg-slate-700 border-slate-500 rounded cursor-pointer" data-group="suspicious" value="${globalIdx}">
                            </td>
                            <td class="px-3 py-2 font-medium text-sm text-yellow-300">${sub.subdomain}</td>
                            <td class="px-3 py-2 font-mono text-xs text-slate-400">${sub.ip_address || '-'}</td>
                            <td class="px-3 py-2 text-slate-400 text-xs">${sub.server_software || '-'}</td>
                        </tr>
                    `;
                });
            }
            
            // Render UNRESOLVABLE list
            if(unresolvableList.length > 0) {
                document.getElementById('section-unresolvable').classList.remove('hidden');
                const ul = document.getElementById('unresolvableList');
                ul.innerHTML = '';
                unresolvableList.forEach(sub => {
                    ul.innerHTML += `<li class="font-mono">💀 ${sub.subdomain}</li>`;
                });
            }
            
            // Render EXTERNAL warning
            if(externalList.length > 0) {
                document.getElementById('section-external').classList.remove('hidden');
                const ul = document.getElementById('externalList');
                ul.innerHTML = '';
                externalList.forEach(sub => {
                    ul.innerHTML += `<li class="font-mono">🚨 ${sub.subdomain}</li>`;
                });
            }
            
            document.getElementById('selectAllActive').checked = false;
            document.getElementById('selectAllSuspicious').checked = false;
            
            updateSelectedCount();
        }
    } catch(e) {
        console.error(e);
        alert("Discovery failed. Check console for details.");
    } finally {
        btn.disabled = false;
        loading.classList.add('hidden');
    }
}

function toggleGroupSelection(group, masterCheckbox) {
    const checkboxes = document.querySelectorAll(`.sub-checkbox[data-group="${group}"]`);
    checkboxes.forEach(c => c.checked = masterCheckbox.checked);
    updateSelectedCount();
}

function updateSelectedCount() {
    const checkboxes = document.querySelectorAll('.sub-checkbox:checked');
    document.getElementById('selectedCount').textContent = checkboxes.length;
    
    const activeCb = document.querySelectorAll('.sub-checkbox[data-group="active"]');
    if (activeCb.length > 0) {
        const activeChecked = document.querySelectorAll('.sub-checkbox[data-group="active"]:checked');
        document.getElementById('selectAllActive').checked = (activeCb.length === activeChecked.length);
    }
    
    const suspCb = document.querySelectorAll('.sub-checkbox[data-group="suspicious"]');
    if (suspCb.length > 0) {
        const suspChecked = document.querySelectorAll('.sub-checkbox[data-group="suspicious"]:checked');
        document.getElementById('selectAllSuspicious').checked = (suspCb.length === suspChecked.length);
    }
    
    const estSecs = checkboxes.length * 3;
    const m = Math.floor(estSecs / 60);
    const s = estSecs % 60;
    document.getElementById('estTime').textContent = `${m}m ${s}s`;
    
    document.getElementById('btnStartScan').disabled = checkboxes.length === 0;
}

async function startDeepScan() {
    const checkboxes = document.querySelectorAll('.sub-checkbox:checked');
    const selectedSubs = Array.from(checkboxes).map(c => allScannable[parseInt(c.value)]);
    
    if(selectedSubs.length === 0) return;
    
    document.getElementById('btnStartScan').disabled = true;
    document.getElementById('progress-container').classList.remove('hidden');
    
    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                domain_id: currentDomainId,
                subdomains: selectedSubs
            })
        });
        
        if(res.ok) {
            const total = selectedSubs.length;
            scanPoller = setInterval(() => checkProgress(total), 2000);
        }
    } catch(e) {
        console.error(e);
        alert("Scan start failed");
    }
}

async function checkProgress(total) {
    try {
        const res = await fetch(`/api/scan/progress/${currentDomainId}`);
        if(res.ok) {
            const data = await res.json();
            const comp = data.completed;
            
            document.getElementById('scanProgressText').textContent = `${comp} / ${total}`;
            const pct = (comp / total) * 100;
            document.getElementById('scanProgressBar').style.width = `${pct}%`;
            
            if(data.status === 'completed' || comp >= total) {
                clearInterval(scanPoller);
                document.getElementById('scanStatusText').textContent = "Scan Completed!";
                document.getElementById('scanStatusText').classList.replace('text-blue-400', 'text-green-400');
                document.getElementById('scanStatusText').classList.remove('animate-pulse');
                
                setTimeout(() => {
                    loadPage('home');
                }, 1500);
            }
        }
    } catch(e) { console.error(e); }
}

window.downloadAttestation = function() {
    let url = '/api/attestation';
    if(currentDomainId) {
        url += `?domain_id=${currentDomainId}`;
    }
    window.location.href = url;
}
