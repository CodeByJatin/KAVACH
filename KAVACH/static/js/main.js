let currentDomainId = null;
let currentDiscoveryDomainId = null;
let currentDiscoveryData = [];
let currentDiscoveryTab = 'domains';
let currentDiscoverySubTab = 'all';
let discoveryPollingInterval = null;
let scanPoller = null;

// ---- TOAST NOTIFICATION SYSTEM ----
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if(!container) return;
    
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        info: 'fa-info-circle',
        warn: 'fa-exclamation-triangle'
    };
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${message}</span>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}

// ---- COPY TO CLIPBOARD ----
window.copyToClipboard = function(text, btnEl) {
    navigator.clipboard.writeText(text).then(() => {
        if(btnEl) {
            btnEl.classList.add('copied');
            const orig = btnEl.innerHTML;
            btnEl.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
                btnEl.classList.remove('copied');
                btnEl.innerHTML = orig;
            }, 1200);
        }
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

document.addEventListener('DOMContentLoaded', () => {
    fetchUserData();
    checkMfaStatus();
    fetchDomains().then(() => {
        loadPage('home');
    });

    document.getElementById('domainSelect').addEventListener('change', (e) => {
        const val = e.target.value;
        currentDomainId = val === 'none' ? null : parseInt(val);
        const activePage = document.querySelector('.nav-link.active').getAttribute('data-page');
        if(activePage) loadPage(activePage);
    });
});

// ---- WEBSOCKETS ----
const socket = window.io ? io() : null;

if (socket) {
    socket.on('connect', () => {
        console.log("Connected to WebSocket");
    });
    
    socket.on('discovery_complete', (data) => {
        if (currentDiscoveryDomainId === data.domain_id) {
            refreshDomainSidebar();
            fetchDiscoveryAssets(currentDiscoveryDomainId);
            showToast('Discovery process completed for domain.', 'success');
        }
    });

    socket.on('discovery_error', (data) => {
        if (currentDiscoveryDomainId === data.domain_id) {
            refreshDomainSidebar();
            showToast('Discovery error: ' + data.error, 'error');
        }
    });

    socket.on('scan_progress', (data) => {
        if (currentDiscoveryDomainId === data.domain_id) {
            const statusBox = document.getElementById('discoveryGlobalStatus');
            if(statusBox) {
                statusBox.innerHTML = `<i class="fas fa-radar fa-spin mr-1 text-yellow-500"></i> Deep Scanning... <b>${data.completed} / ${data.total}</b>`;
            }
        }
    });

    socket.on('scan_complete', (data) => {
        if (currentDiscoveryDomainId === data.domain_id) {
            refreshDomainSidebar();
            fetchDiscoveryAssets(currentDiscoveryDomainId);
            showToast('Deep scan completed for domain.', 'success');
        }
    });
}

// ---- MFA BUTTON LOGIC ----
async function checkMfaStatus() {
    try {
        const res = await fetch('/api/mfa-status');
        if(res.ok) {
            const data = await res.json();
            const btn = document.getElementById('mfaHeaderBtn');
            if(btn) {
                if(data.mfa_enabled) {
                    btn.innerHTML = `<i class="fas fa-shield-alt text-sm group-hover:scale-110 transition-transform text-green-400"></i><span>MFA Enabled</span>`;
                    btn.classList.remove('border-white/20');
                    btn.classList.add('border-green-500/40', 'bg-green-500/10');
                } else {
                    btn.innerHTML = `<i class="fas fa-user-shield text-sm group-hover:scale-110 transition-transform"></i><span>Enable MFA</span>`;
                }
            }
        }
    } catch(e) { console.error(e); }
}

async function handleMfaButtonClick() {
    try {
        const res = await fetch('/api/mfa-status');
        if(res.ok) {
            const data = await res.json();
            if(data.mfa_enabled) {
                // Show the "already enabled" modal
                document.getElementById('mfaEnabledModal').classList.remove('hidden');
            } else {
                // Redirect to MFA setup page
                window.location.href = '/setup-mfa?from=dashboard';
            }
        }
    } catch(e) {
        showToast('Failed to check MFA status', 'error');
    }
}

function closeMfaModal() {
    document.getElementById('mfaEnabledModal').classList.add('hidden');
}

// ---- KAVACH AI CHAT LOGIC ----
let chatAbortController = null;
let currentChatAssetId = null;

let chatHistoryLoaded = false;

window.toggleChat = function() {
    const panel = document.getElementById('chatPanel');
    panel.classList.toggle('hidden');
    if(!panel.classList.contains('hidden')) {
        document.getElementById('chatInput').focus();
        if(!chatHistoryLoaded) {
            loadChatHistory();
        }
    }
}

async function loadChatHistory() {
    try {
        const res = await fetch('/api/chat/history');
        if(res.ok) {
            const history = await res.json();
            if(history.length > 0) {
                const container = document.getElementById('chatMessages');
                container.innerHTML = ''; // Clear default welcome message
                history.forEach(msg => {
                    const isAi = msg.role === 'assistant';
                    let content = msg.content;
                    
                    // Parse AI HTML securely if marked is used
                    if (isAi && window.marked) {
                        content = marked.parse(content);
                    }
                    
                    // The appendMessage function normally expects plain text/HTML depending on generation
                    // We can reuse it with a slight modification or just pass the string.
                    appendMessage(content, isAi ? 'ai' : 'user', null, true);
                });
            }
            chatHistoryLoaded = true;
        }
    } catch(e) { console.error("Failed to load chat history", e); }
}

async function handleChatSubmit(e) {
    e.preventDefault();
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    if(!message) return;

    input.value = '';
    appendMessage(message, 'user');
    
    // Add loading indicator from AI
    const loadingId = 'ai-loading-' + Date.now();
    appendMessage('<i class="fas fa-spinner fa-spin mr-2"></i> KAVACH AI is thinking...', 'ai', loadingId);

    const stopBtn = document.getElementById('chatStopBtn');
    const submitBtn = document.getElementById('chatSubmitBtn');
    if (stopBtn) stopBtn.classList.remove('hidden');
    if (submitBtn) submitBtn.classList.add('hidden');

    chatAbortController = new AbortController();

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, asset_id: currentChatAssetId }),
            signal: chatAbortController.signal
        });
        
        currentChatAssetId = null; // reset after sending

        const loadingEl = document.getElementById(loadingId);
        if (response.status === 503) {
            const data = await response.json();
            loadingEl.innerHTML = `<span class="text-red-400 font-bold"><i class="fas fa-exclamation-triangle mr-1"></i> ${data.error}</span><br><p class="mt-1 text-[11px]">${data.instruction}</p>`;
            return;
        }

        if (!response.ok) throw new Error('Failed to connect to AI');

        // Handle streaming response
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        loadingEl.innerHTML = ''; // Clear loading text
        let fullResponse = '';
        
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value, { stream: true });
            fullResponse += chunk;
            
            // Parse markdown using marked.js
            if(window.marked) {
                loadingEl.innerHTML = marked.parse(fullResponse);
            } else {
                loadingEl.innerHTML += chunk;
            }
            
            // Auto-scroll as text streams
            const chatContainer = document.getElementById('chatMessages');
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }

    } catch (error) {
        console.error(error);
        const loadingEl = document.getElementById(loadingId);
        if (error.name === 'AbortError') {
            if(loadingEl) loadingEl.innerHTML += '<br><span class="text-yellow-500 text-[10px]"><i class="fas fa-stop-circle mr-1"></i> Generation stopped by user.</span>';
        } else {
            if(loadingEl) loadingEl.innerHTML = '<span class="text-red-400">Error: Could not reach the AI backend. Make sure Ollama is running.</span>';
        }
    } finally {
        if (stopBtn) stopBtn.classList.add('hidden');
        if (submitBtn) submitBtn.classList.remove('hidden');
        chatAbortController = null;
    }
}

window.stopAi = function() {
    if (chatAbortController) {
        chatAbortController.abort();
    }
}

function appendMessage(content, role, id = null) {
    const container = document.getElementById('chatMessages');
    const msgDiv = document.createElement('div');
    msgDiv.className = `flex ${role === 'user' ? 'justify-end' : 'justify-start'}`;
    
    const innerClass = role === 'user' 
        ? 'bg-gradient-to-br from-yellow-500 to-yellow-600 text-rose-950 font-medium rounded-2xl rounded-tr-none' 
        : 'bg-slate-800 border border-slate-700 text-slate-200 rounded-2xl rounded-tl-none';
    
    const contentClass = role === 'user' ? 'text-xs leading-relaxed' : 'text-xs leading-relaxed ai-message-content';
    
    msgDiv.innerHTML = `
        <div class="${innerClass} p-3 max-w-[85%] shadow-sm animate-fade-in" style="overflow-wrap:break-word;word-break:break-word;overflow:hidden;">
            <div class="${contentClass}" ${id ? `id="${id}"` : ''} style="overflow-wrap:break-word;word-break:break-word;">${content}</div>
        </div>
    `;
    
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

window.askAi = function(predefinedMessage, assetId = null) {
    const panel = document.getElementById('chatPanel');
    if(panel.classList.contains('hidden')) toggleChat();
    
    const input = document.getElementById('chatInput');
    input.value = predefinedMessage;
    currentChatAssetId = assetId;
    
    // Trigger submit manually
    document.getElementById('chatForm').dispatchEvent(new Event('submit'));
}

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
            while(select.options.length > 1) { select.remove(1); }
            
            domains.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = `${d.domain_name} (${d.status})`;
                if(currentDomainId === d.id) opt.selected = true;
                select.appendChild(opt);
            });
        }
    } catch(e) { console.error(e); }
}

async function loadPage(pageName) {
    // WebSockets handle live updates now, no more intervals needed!
    if(discoveryPollingInterval) {
        clearInterval(discoveryPollingInterval);
        discoveryPollingInterval = null;
    }

    document.querySelectorAll('.nav-link').forEach(el => {
        el.classList.remove('active');
        el.classList.add('text-slate-300');
    });
    
    const activeLink = document.querySelector(`.nav-link[data-page="${pageName}"]`);
    if(activeLink) {
        activeLink.classList.add('active');
        activeLink.classList.remove('text-slate-300');
    }
    
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
            const mainEl = document.getElementById('mainContent');
            mainEl.innerHTML = html;
            
            mainEl.classList.add('stagger-children');
            setTimeout(() => mainEl.classList.remove('stagger-children'), 800);
            
            if(pageName === 'home') initDashboard();
            if(pageName === 'cbom') initCBOM();
            if(pageName === 'posture') initPosture();
            if(pageName === 'rating') initRating();
            if(pageName === 'discovery') initDiscovery();
            if(pageName === 'add_domain') initAddDomain();
            
        } else {
            document.getElementById('mainContent').innerHTML = `<p class="text-red-500">Error loading page.</p>`;
            showToast('Failed to load page', 'error');
        }
    } catch(e) { console.error(e); }
}

// ---- DASHBOARD ----
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
    
    dashboardMap = L.map('dashboardMap', { center: [20.5937, 78.9629], zoom: 4, zoomControl: true, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(dashboardMap);
    
    const seenIPs = new Set();
    assets.forEach(asset => {
        const ip = asset.ip_address;
        const lat = asset.latitude;
        const lng = asset.longitude;
        if(!ip || !lat || !lng || seenIPs.has(ip)) return;
        seenIPs.add(ip);
        const scoreColor = asset.pqc_score > 700 ? '#22c55e' : asset.pqc_score >= 400 ? '#eab308' : asset.pqc_score >= 100 ? '#f97316' : '#ef4444';
        const marker = L.circleMarker([lat + (Math.random()-0.5)*0.5, lng + (Math.random()-0.5)*0.5], { radius: 6, fillColor: scoreColor, color: scoreColor, weight: 1, opacity: 0.9, fillOpacity: 0.7 }).addTo(dashboardMap);
        marker.bindPopup(`<div style="font-family:Inter;font-size:12px;color:#1e293b;min-width:180px"><b>${asset.subdomain}</b><br>IP: <code>${ip}</code><br>Score: <b>${asset.pqc_score || 0}</b></div>`);
    });
    setTimeout(() => { if(dashboardMap) dashboardMap.invalidateSize(); }, 200);
}

function renderDashMiniTable(assets) {
    const tbody = document.getElementById('dashMiniTableBody');
    if(!tbody) return;
    
    const top = assets.slice(0, 10);
    let html = '';
    
    top.forEach(item => {
        let badgeClass = item.pqc_score > 700 ? 'bg-green-500/20 text-green-400' : item.pqc_score >= 400 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-500';
        html += `<tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-3 font-medium text-white">${item.subdomain}</td>
                    <td class="px-6 py-3 text-slate-400 font-mono text-xs">${item.open_ports ? item.open_ports.replace(/, /g, '<br>') : '-'}</td>
                    <td class="px-6 py-3 text-slate-400">${item.tls_version || '-'}</td>
                    <td class="px-6 py-3 font-bold text-white">${item.pqc_score || 0}</td>
                    <td class="px-6 py-3"><span class="px-2 py-0.5 rounded text-xs ${badgeClass}">Analyzed</span></td>
                </tr>`;
    });
    
    tbody.innerHTML = html || '<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500">No scanned assets yet. Add a domain and run a deep scan.</td></tr>';
}

// ---- POSTURE ----
let currentPostureData = [];

async function initPosture() {
    try {
        const url = currentDomainId ? `/api/posture/${currentDomainId}` : '/api/posture';
        const res = await fetch(url);
        if(res.ok) {
            currentPostureData = await res.json();
            
            // Calculate Global Stats
            if (currentPostureData.length > 0) {
                const totalScore = currentPostureData.reduce((acc, a) => acc + (a.pqc_score || 0), 0);
                const avgScore = Math.round(totalScore / currentPostureData.length);
                const eliteCount = currentPostureData.filter(a => a.pqc_score > 700).length;
                const criticalCount = currentPostureData.filter(a => a.pqc_score < 400).length;
                
                const elScore = document.getElementById('avgPostureScore');
                const elElite = document.getElementById('elitePostureCount');
                const elCrit = document.getElementById('criticalPostureCount');
                
                if(elScore) elScore.textContent = avgScore;
                if(elElite) elElite.textContent = eliteCount;
                if(elCrit) elCrit.textContent = criticalCount;
            }
            
            renderPostureTable(currentPostureData);
        }
    } catch(e) { console.error(e); }
}

function renderPostureTable(data) {
    const tbody = document.getElementById('postureTableBody');
    if(!tbody) return;
    
    let html = '';
    data.forEach(item => {
        const safeData = encodeURIComponent(JSON.stringify(item));
        html += `
            <tr class="hover:bg-slate-800/50 transition-colors">
                <td class="px-6 py-4 font-medium">${item.subdomain}</td>
                <td class="px-6 py-4 text-slate-400 text-xs font-mono">${item.open_ports ? item.open_ports.replace(/, /g, '<br>') : '-'}</td>
                <td class="px-6 py-4 text-slate-400 text-xs">${item.tls_version || '-'}</td>
                <td class="px-6 py-4 text-slate-400 text-xs font-mono break-all">${item.cipher_suite || '-'}</td>
                <td class="px-4 py-4 text-slate-400 text-sm">
                    <div class="font-bold text-white">${item.key_type || 'Unknown'}</div>
                    <div class="text-xs">${item.key_length || '-'} bits</div>
                </td>
                <td class="px-4 py-4 font-bold ${item.pqc_score > 700 ? 'text-green-400' : 'text-slate-300'}">${item.pqc_score || 0}</td>
                <td class="px-6 py-4 text-center">
                    <button onclick="openPQCModal('${safeData}')" class="px-3 py-1 bg-slate-700 hover:bg-slate-600 border border-slate-500 text-white text-xs rounded transition-colors shadow-sm mb-1 w-full">
                        <i class="fas fa-search-plus mr-1 text-yellow-400"></i> Inspect
                    </button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html || '<tr><td colspan="7" class="px-6 py-8 text-center text-slate-500">No assets found matching the filter.</td></tr>';
}

window.openPQCModal = function(safeDataStr) {
    const data = JSON.parse(decodeURIComponent(safeDataStr));
    document.getElementById('modalSubdomain').textContent = data.subdomain || 'Unknown';
    document.getElementById('modalCA').textContent = data.cert_authority || 'Unknown Provider';
    const elScoreBadge = document.getElementById('modalScoreBadge');
    elScoreBadge.textContent = data.pqc_score || 0;
    const details = data.pqc_details || {};
    document.getElementById('modalTlsScore').textContent = `+${details.tls_score || 0} pts`;
    document.getElementById('modalCipherScore').textContent = `+${details.cipher_score || 0} pts`;
    document.getElementById('modalKeyScore').textContent = `+${details.key_score || 0} pts`;
    document.getElementById('modalPqcScore').textContent = `+${details.compliance_score || 0} pts`;
    document.getElementById('modalKeyType').textContent = data.key_type || 'Unknown';
    document.getElementById('modalKeyLength').textContent = `${data.key_length || 0} bits`;
    
    // Inject dynamic Ask AI prompt that includes comprehensive context
    const aiPrompt = `Give extremely concise, genuine advice for ${data.subdomain}. Do NOT write a long paragraph. Context: TLS Phase (${data.tls_version || 'Unknown'}), Cipher Suite (${data.cipher_suite || 'Unknown'}), Key: ${data.key_type || 'Unknown'} ${data.key_length || 0}-bit, CA: ${data.cert_authority || 'Unknown'}, Overall Score: ${data.pqc_score || 0}.`;
    
    const aiBtn = document.getElementById('btnAskPqcAi');
    if(aiBtn) aiBtn.setAttribute('onclick', `askAi(${JSON.stringify(aiPrompt)})`);
    
    document.getElementById('pqcModal').classList.remove('hidden');
}

window.closePQCModal = function() { document.getElementById('pqcModal').classList.add('hidden'); }

async function initDiscovery() {
    renderDiscoveryTableHeader();
    
    // Always sync with top-left dashboard scroller context
    if (currentDomainId) {
        currentDiscoveryDomainId = currentDomainId;
    }
    
    await refreshDomainSidebar();
    // Removed polling: if(!discoveryPollingInterval) { discoveryPollingInterval = setInterval(refreshDomainSidebar, 3000); }
}

async function refreshDomainSidebar() {
    try {
        const res = await fetch('/api/my-domains');
        if(!res.ok) return;
        const domains = await res.json();
        const list = document.getElementById('domainSidebarList');
        if(!list) return;
        
        // Preserve scroll position
        const scrollTop = list.scrollTop;
        let listHtml = '';
        
        domains.forEach(d => {
            const isActive = currentDiscoveryDomainId === d.id;
            
            // Dynamic UI Trackers
            let statusIcon, statusText;
            if (d.discovery_status === 'discovering') {
                statusIcon = '<i class="fas fa-satellite-dish fa-spin text-blue-400"></i>';
                statusText = 'Discovering...';
            } else if (d.status === 'scanning') {
                statusIcon = '<i class="fas fa-radar fa-spin text-yellow-500"></i>';
                statusText = 'Deep Scanning...';
            } else if (d.discovery_status === 'completed' && d.status === 'completed') {
                statusIcon = '<i class="fas fa-check-circle text-green-400"></i>';
                statusText = 'Analyzed';
            } else if (d.discovery_status === 'completed') {
                statusIcon = '<i class="fas fa-list text-blue-300"></i>';
                statusText = 'Ready to Scan';
            } else {
                statusIcon = '<i class="fas fa-clock text-slate-500"></i>';
                statusText = 'Pending';
            }
            
            const btnClass = `w-full text-left p-3 rounded-lg flex items-center justify-between transition-all border ${isActive ? 'bg-yellow-500/10 border-yellow-500/40' : 'bg-white/5 border-transparent hover:bg-white/10'}`;
            listHtml += `<button onclick="selectDiscoveryDomain(${d.id})" class="${btnClass}">
                            <div class="flex flex-col min-w-0">
                                <span class="text-sm font-semibold text-white truncate">${d.domain_name}</span>
                                <span class="text-[10px] text-slate-400">${statusText}</span>
                            </div>
                            <div class="flex-shrink-0 ml-2">${statusIcon}</div>
                         </button>`;
        });
        
        list.innerHTML = listHtml;
        list.scrollTop = scrollTop; // Restore scroll
        
        if(!currentDiscoveryDomainId && domains.length > 0) { 
            await selectDiscoveryDomain(domains[0].id); 
        } else if (currentDiscoveryDomainId) {
            const current = domains.find(d => d.id === currentDiscoveryDomainId);
            const statusBox = document.getElementById('discoveryGlobalStatus');
            if(statusBox) {
                if(current && current.discovery_status === 'discovering') {
                    statusBox.innerHTML = `<i class="fas fa-spinner fa-spin mr-1"></i> Discovering <b>${current.domain_name}</b>...`;
                } else if(current && current.status === 'scanning') {
                    statusBox.innerHTML = `<i class="fas fa-radar fa-spin mr-1 text-yellow-500"></i> Deep Scanning <b>${current.domain_name}</b>...`;
                } else {
                    statusBox.textContent = "Discovery engine idle.";
                }
            }
            
            // No need to fetch assets periodically anymore since we have WebSockets
        }
    } catch(e) { console.error(e); }
}

async function selectDiscoveryDomain(id) {
    currentDiscoveryDomainId = id;
    await refreshDomainSidebar();
    await fetchDiscoveryAssets(id);
}

async function fetchDiscoveryAssets(id) {
    try {
        const res = await fetch(`/api/discovery-assets/${id}`);
        if(res.ok) {
            const data = await res.json();
            currentDiscoveryData = [...data.active, ...data.suspicious];
            renderDiscoveryTable();
            document.getElementById('countDomains').textContent = `(${data.counts.active})`;
            document.getElementById('countAll').textContent = `(${data.counts.active + data.counts.suspicious})`;
        }
    } catch(e) { console.error(e); }
}

function renderDiscoveryTableHeader() {
    const thead = document.getElementById('discoveryTableHeader');
    if(!thead) return;
    
    let html = `<tr><th class="px-6 py-4 w-10"><input type="checkbox" id="selectAllDiscovery" onchange="toggleSelectAllDiscovery(this)" class="w-4 h-4 text-yellow-600 bg-slate-700 border-slate-500 rounded cursor-pointer"></th>`;
    html += `<th class="px-6 py-4">Status</th><th class="px-6 py-4">Subdomain</th>`;
    
    if (currentDiscoveryTab === 'ips') {
        html += `<th class="px-6 py-4">IP Address</th><th class="px-6 py-4">Open Ports</th><th class="px-6 py-4">Location</th>`;
    } else if (currentDiscoveryTab === 'ssl') {
        html += `<th class="px-6 py-4">TLS Version</th><th class="px-6 py-4">Cipher Suite</th>`;
    } else if (currentDiscoveryTab === 'software') {
        html += `<th class="px-6 py-4">Server / Framework</th><th class="px-6 py-4">IP Address</th>`;
    } else {
        html += `<th class="px-6 py-4">IP Address</th><th class="px-6 py-4">Open Ports</th>`;
    }
    
    html += `<th class="px-6 py-4 text-right">Actions</th></tr>`;
    thead.innerHTML = html;
}

function renderDiscoveryTable() {
    const tbody = document.getElementById('discoveryTableBody');
    if(!tbody) return;
    
    let displayData = currentDiscoveryData;
    if(currentDiscoverySubTab === 'new') displayData = currentDiscoveryData.filter(d => !d.pqc_score);
    if(currentDiscoverySubTab === 'confirmed') displayData = currentDiscoveryData.filter(d => d.pqc_score > 400);

    let html = '';
    displayData.forEach(item => {
        let statHtml = item.pqc_score ? `<span class="px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 text-[10px]">Analyzed</span>` : (item.pqc_status === 'suspicious' ? `<span class="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 text-[10px]">Suspicious</span>` : `<span class="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-[10px]">New</span>`);
        
        html += `<tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-4">
                        <input type="checkbox" class="discovery-checkbox w-4 h-4 text-yellow-600 bg-slate-700 border-slate-500 rounded cursor-pointer" value="${item.id}" onchange="updateDiscoverySelectionUI()">
                    </td>
                    <td class="px-6 py-4">${statHtml}</td>
                    <td class="px-6 py-4 font-medium text-white">${item.subdomain}</td>`;
                    
        if (currentDiscoveryTab === 'ips') {
            const loc = (item.city || item.country) ? `${item.city || ''}, ${item.country || ''}`.replace(/^, /, '') : '-';
            html += `<td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.ip_address || '-'}</td>`;
            html += `<td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.open_ports || '-'}</td>`;
            html += `<td class="px-6 py-4 text-slate-400 text-xs">${loc}</td>`;
        } else if (currentDiscoveryTab === 'ssl') {
            html += `<td class="px-6 py-4 text-slate-400 text-xs">${item.tls_version || '-'}</td>`;
            html += `<td class="px-6 py-4 text-slate-400 text-xs font-mono">${item.cipher_suite || '-'}</td>`;
        } else if (currentDiscoveryTab === 'software') {
            html += `<td class="px-6 py-4 text-slate-400 text-xs">${item.server_software || '-'}</td>`;
            html += `<td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.ip_address || '-'}</td>`;
        } else {
            html += `<td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.ip_address || '-'}</td>`;
            html += `<td class="px-6 py-4 text-slate-400 font-mono text-xs">${item.open_ports || '-'}</td>`;
        }
        
        html += `<td class="px-6 py-4 text-right">
                        <button onclick="scanSingleAsset(${item.id})" class="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-600 transition-colors">
                            <i class="fas fa-satellite-dish mr-1 text-yellow-500"></i> Deep Scan
                        </button>
                    </td>
                </tr>`;
    });
    
    tbody.innerHTML = html || '<tr><td colspan="8" class="px-6 py-12 text-center text-slate-500 italic">No assets found for this domain yet. Discovery may be in progress.</td></tr>';
}

function updateDiscoverySelectionUI() {
    const checked = document.querySelectorAll('.discovery-checkbox:checked');
    const actions = document.getElementById('selectionActions');
    if(actions) {
        if(checked.length > 0) actions.classList.remove('hidden');
        else actions.classList.add('hidden');
    }
}

function toggleSelectAllDiscovery(el) {
    const checks = document.querySelectorAll('.discovery-checkbox');
    checks.forEach(c => c.checked = el.checked);
    updateDiscoverySelectionUI();
}

async function scanSelectedDiscovery() {
    const checked = document.querySelectorAll('.discovery-checkbox:checked');
    const assetIds = Array.from(checked).map(c => parseInt(c.value));
    const selectedAssets = currentDiscoveryData.filter(a => assetIds.includes(a.id));
    showToast(`Initiating scan for ${selectedAssets.length} assets...`, 'info');
    try {
        const res = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ domain_id: currentDiscoveryDomainId, subdomains: selectedAssets }) });
        if(res.ok) { showToast('Scan started.', 'success'); }
    } catch(e) { console.error(e); }
}

async function scanSingleAsset(id) {
    const asset = currentDiscoveryData.find(a => a.id === id);
    if(!asset) return;
    showToast(`Scanning ${asset.subdomain}...`, 'info');
    try {
        const res = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ domain_id: currentDiscoveryDomainId, subdomains: [asset] }) });
        if(res.ok) { showToast('Scan started.', 'success'); }
    } catch(e) { console.error(e); }
}

// ---- ADD DOMAIN ----
function initAddDomain() {}

async function startDiscovery(e) {
    e.preventDefault();
    const domain = document.getElementById('domainInput').value;
    const btn = document.getElementById('btnDiscover');
    const loading = document.getElementById('loadingStatus1');
    btn.disabled = true;
    loading.classList.remove('hidden');
    try {
        const res = await fetch('/api/discover', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({domain}) });
        if(res.ok) {
            const data = await res.json();
            currentDiscoveryDomainId = data.domain_id;
            currentDomainId = data.domain_id;
            
            await fetchDomains();
            document.getElementById('domainSelect').value = currentDomainId;
            
            showToast('Target domain added. Discovery started.', 'success');
            setTimeout(() => { loadPage('discovery'); }, 1000);
        } else { showToast('Failed to start discovery', 'error'); btn.disabled = false; loading.classList.add('hidden'); }
    } catch(e) { console.error(e); btn.disabled = false; loading.classList.add('hidden'); }
}

// ---- RATING & SCAN PROGRESS ----
async function initRating() {
    try {
        const url = currentDomainId ? `/api/rating/${currentDomainId}` : '/api/rating';
        const res = await fetch(url);
        if(res.ok) {
            const data = await res.json();
            const ratingScore = data.average_score;
            document.getElementById('ratingScore').textContent = ratingScore;
            document.getElementById('ratingLabel').textContent = data.rating;
            
            // Dynamic Pie Chart Logic
            const ring = document.getElementById('ratingRing');
            if (ring) {
                const offset = 251.2 - (251.2 * (ratingScore / 1000));
                ring.style.strokeDashoffset = offset;
                
                const glow = document.getElementById('ratingGlow');
                let colorClass = 'text-red-500';
                let glowColor = 'bg-red-500';
                if(ratingScore > 700) { colorClass = 'text-green-500'; glowColor = 'bg-green-500'; }
                else if(ratingScore >= 400) { colorClass = 'text-yellow-500'; glowColor = 'bg-yellow-500'; }
                else if(ratingScore >= 100) { colorClass = 'text-orange-500'; glowColor = 'bg-orange-500'; }
                
                ring.className = `transition-all duration-1000 ease-out ${colorClass}`;
                if(glow) glow.className = `absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 rounded-full mix-blend-screen filter blur-[128px] opacity-20 pointer-events-none ${glowColor}`;
            }
        }
    } catch(e) { console.error(e); }
}

window.downloadAttestation = function() {
    const val = document.getElementById('domainSelect').value;
    window.location.href = val === 'none' ? '/api/attestation' : '/api/attestation/' + val;
}


async function initCBOM() {
    try {
        const url = currentDomainId ? `/api/cbom/${currentDomainId}` : '/api/cbom';
        const res = await fetch(url);
        if(res.ok) {
            const data = await res.json();
            if(window.renderCharts) window.renderCharts(data);
        }
    } catch(e) { console.error(e); }
}

window.switchDiscoverySubTab = function(sub) { 
    currentDiscoverySubTab = sub; 
    
    // Update UI highlighting
    ['all', 'new', 'confirmed'].forEach(s => {
        const btn = document.getElementById(`subTabBtn-${s}`);
        if(btn) {
            if(s === sub) {
                btn.classList.add('text-yellow-400', 'border-yellow-400');
                btn.classList.remove('text-slate-400');
            } else {
                btn.classList.remove('text-yellow-400', 'border-yellow-400');
                btn.classList.add('text-slate-400');
            }
        }
    });

    renderDiscoveryTable(); 
}

window.switchDiscoveryTab = function(tab) { 
    currentDiscoveryTab = tab; 
    
    // Update UI highlighting
    ['domains', 'ssl', 'ips', 'software'].forEach(t => {
        const btn = document.getElementById(`tabBtn-${t}`);
        if(btn) {
            if(t === tab) {
                btn.classList.add('text-rose-900', 'bg-yellow-500', 'shadow-sm');
                btn.classList.remove('text-white', 'hover:bg-white/10');
            } else {
                btn.classList.remove('text-rose-900', 'bg-yellow-500', 'shadow-sm');
                btn.classList.add('text-white', 'hover:bg-white/10');
            }
        }
    });

    renderDiscoveryTableHeader(); 
    renderDiscoveryTable(); 
}
