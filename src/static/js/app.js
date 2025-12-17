// Main application JavaScript

// Check auth status first, but don't block page loading
async function initAuth() {
    try {
        const response = await fetch('/api/v1/auth/status');
        if (!response.ok) {
            // If endpoint doesn't exist or returns error, redirect to login
            if (window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
                window.location.href = '/login';
            }
            return false;
        }
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            // Not JSON response, redirect to login
            if (window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
                window.location.href = '/login';
            }
            return false;
        }
        const data = await response.json();
        
        // Check if setup is required
        if (data.needs_setup) {
            // Redirect to setup page
            if (window.location.pathname !== '/setup') {
                window.location.href = '/setup';
            }
            return false;
        }
        
        if (!data.authenticated) {
            // Not authenticated, redirect to login
            if (window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
                window.location.href = '/login';
            }
            return false;
        }
        
        // Authenticated
        return true;
    } catch (error) {
        // If there's an error, redirect to login
        console.error('Auth check error:', error);
        if (window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
            window.location.href = '/login';
        }
        return false;
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    // Check authentication first
    const isAuthenticated = await initAuth();
    if (!isAuthenticated) {
        return; // Stop execution if not authenticated
    }
    
    // Load local IP status interval
    loadLocalIPStatusInterval();
    // Load auto-update interval
    loadAutoUpdateInterval();
    
    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Function to switch to a specific tab
    function switchToTab(targetTab) {
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        const targetBtn = document.querySelector(`.tab-btn[data-tab="${targetTab}"]`);
        const targetContent = document.getElementById(targetTab + 'Tab');
        
        if (targetBtn && targetContent) {
            targetBtn.classList.add('active');
            targetContent.classList.add('active');
            
            // Save active tab to localStorage
            localStorage.setItem('activeTab', targetTab);
            
            // Stop all health checks when switching tabs
            stopAllHealthChecks();
            
            // Load zones and public IP when zones tab is opened
            if (targetTab === 'zones') {
                loadZones();
                loadPublicIP();
            }
            
            // Load API tokens when config tab is opened
            if (targetTab === 'config') {
                loadApiTokens();
                loadMachineName();
            }
            
            // Load security config when security tab is opened
            if (targetTab === 'security') {
                loadSecurityConfig();
            }
            
            // Load audit logs when audit-logs tab is opened
            if (targetTab === 'audit-logs') {
                loadAuditLogs();
                loadAuditLogSettings();
            }
        }
    }
    
    // Restore active tab from localStorage on page load
    const savedTab = localStorage.getItem('activeTab');
    if (savedTab) {
        // Remove active class from default tab first
        tabBtns.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        // Switch to saved tab
        switchToTab(savedTab);
    }
    
    // Add click listeners to tab buttons
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            switchToTab(targetTab);
        });
    });
    
    // Logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async function() {
            try {
                await fetch('/api/v1/auth/logout', { method: 'POST' });
                window.location.href = '/login';
            } catch (error) {
                console.error('Logout error:', error);
            }
        });
    }
    
    // Load API tokens
    loadApiTokens();
    
    // Load zones and public IP when page loads
    loadZones();
    loadPublicIP();
    
    // Legacy token buttons removed - use addNewToken() instead
    
    // Add token button
    const addTokenBtn = document.getElementById('addTokenBtn');
    if (addTokenBtn) {
        addTokenBtn.addEventListener('click', addNewToken);
    }
});

async function refreshZones() {
    const btn = document.getElementById('refreshZonesBtn');
    const originalText = btn ? btn.textContent : 'Refresh Zones';
    const originalDisabled = btn ? btn.disabled : false;
    
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Updating...';
        btn.style.opacity = '0.6';
        btn.style.cursor = 'wait';
    }
    
    try {
        await loadZones();
        showToast('Zones successfully updated', 'success');
    } catch (error) {
        showToast('Error updating zones: ' + error.message, 'error');
        console.error('Error refreshing zones:', error);
    } finally {
        if (btn) {
            btn.disabled = originalDisabled;
            btn.textContent = originalText;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
        }
    }
}

async function loadZones() {
    const zonesListDiv = document.getElementById('zonesList');
    if (!zonesListDiv) return;
    
    zonesListDiv.innerHTML = '<p>Loading zones...</p>';
    
    try {
        // First, get all tokens
        const tokensResponse = await fetch('/api/v1/config/api-tokens');
        if (!tokensResponse.ok) {
            zonesListDiv.innerHTML = '<p class="error">Error loading tokens</p>';
            return;
        }
        const tokensData = await tokensResponse.json();
        const tokens = tokensData.tokens || [];
        
        if (tokens.length === 0) {
            zonesListDiv.innerHTML = `
                <div style="margin-bottom: 8px;">
                    <button class="btn btn-primary" onclick="showCreateZoneDialog()" style="margin-bottom: 0;">
                        + Create New Zone
                    </button>
                </div>
                <p style="color: #666; font-style: italic;">No API tokens configured. Please add a token in the "API Token Configuration" tab.</p>
            `;
            return;
        }
        
        // Load zones for each token
        let allZones = [];
        const zonesByToken = {};
        
        for (const token of tokens) {
            try {
                const response = await fetch(`/api/v1/zones?token_id=${encodeURIComponent(token.id)}`);
                if (response.ok) {
                    const data = await response.json();
                    const zones = data.zones || [];
                    zonesByToken[token.id] = {
                        tokenName: token.name,
                        zones: zones
                    };
                    // Add token_id to each zone for later use
                    zones.forEach(zone => {
                        zone.token_id = token.id;
                        zone.token_name = token.name;
                    });
                    allZones = allZones.concat(zones);
                } else {
                    console.warn(`Failed to load zones for token ${token.name}:`, response.status);
                }
            } catch (error) {
                console.error(`Error loading zones for token ${token.name}:`, error);
            }
        }
        
        // Button zum Erstellen neuer Zonen
        let zonesHTML = `
            <div style="margin-bottom: 8px;">
                <button class="btn btn-primary" onclick="showCreateZoneDialog()" style="margin-bottom: 0;">
                    + Create New Zone
                </button>
            </div>
        `;
        
        if (allZones.length === 0) {
            zonesHTML += '<p style="color: #666; font-style: italic;">No zones found for any token</p>';
            zonesListDiv.innerHTML = zonesHTML;
            return;
        }
        
        // Group zones by token
        zonesHTML += '<div class="zones-table-container">';
        
        for (const tokenId in zonesByToken) {
            const tokenData = zonesByToken[tokenId];
            if (tokenData.zones.length === 0) continue;
            
            // Token header
            zonesHTML += `
                <div style="margin: 20px 0 10px 0; padding: 10px; background: #f5f5f5; border-left: 4px solid #007bff; border-radius: 4px;">
                    <h3 style="margin: 0; font-size: 1.1em;">Token: ${escapeHtml(tokenData.tokenName)}</h3>
                    <small style="color: #666;">${tokenData.zones.length} zone(s)</small>
                </div>
            `;
            
            // Zones for this token
            for (const zone of tokenData.zones) {
                const zoneId = String(zone.id || '');
                const zoneName = String(zone.name || 'N/A');
                const zoneIdEscaped = escapeHtml(zoneId);
                const zoneNameEscaped = escapeHtml(zoneName);
                
                // Load RRSets for this zone
                loadZoneRRSets(zoneId, zoneName, tokenId);
            zonesHTML += `
                <div class="zone-section" data-token-id="${tokenId}">
                    <div class="zone-header" onclick="toggleZoneTable('${zoneIdEscaped}')" style="cursor: pointer;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="display: flex; align-items: center; gap: 10px; flex: 1;">
                                <span class="zone-toggle-icon" id="toggle-icon-${zoneIdEscaped}">▼</span>
                                <div>
                                    <h3 style="margin: 0;">${zoneNameEscaped}</h3>
                                    <div class="zone-meta">
                                        <span><strong>ID:</strong> ${zoneIdEscaped}</span>
                                        <span><strong>TTL:</strong> ${zone.ttl || 'N/A'}</span>
                                        ${zone.created ? `<span><strong>Created:</strong> ${new Date(zone.created).toLocaleString('en-US')}</span>` : ''}
                                    </div>
                                </div>
                            </div>
                            <button class="btn btn-danger btn-small" data-zone-id="${zoneIdEscaped}" data-zone-name="${zoneNameEscaped}" data-token-id="${tokenId}" onclick="event.stopPropagation(); showDeleteZoneDialog(this.dataset.zoneId, this.dataset.zoneName, this.dataset.tokenId)" title="Delete Zone">Delete Zone</button>
                        </div>
                    </div>
                    <div id="zone-content-${zoneIdEscaped}" class="zone-content collapsed" data-token-id="${tokenId}">
                        <div id="rrsets-${zoneIdEscaped}" class="rrsets-loading">Loading entries...</div>
                    </div>
                </div>
            `;
            }
        }
        
        zonesHTML += '</div>';
        zonesListDiv.innerHTML = zonesHTML;
        
        // Load RRSets for each zone
        for (const tokenId in zonesByToken) {
            for (const zone of zonesByToken[tokenId].zones) {
                loadZoneRRSets(zone.id, zone.name, tokenId);
            }
        }
        
    } catch (error) {
        zonesListDiv.innerHTML = `<p class="error">Error loading zones: ${error.message}</p>`;
        console.error('Error loading zones:', error);
    }
}


let publicIPIntervalTimer = null;


// Allowed interval values for public IP refresh
const allowedPublicIPIntervalValues = [10, 30, 60, 300, 600, 1800, 3600];

// Allowed interval values for monitor IP status check
const allowedMonitorIPIntervalValues = [5, 10, 30, 60, 300, 600, 1800, 3600];

// Allowed interval values for auto-update check
const allowedAutoUpdateIntervalValues = [60, 300, 600, 1800, 3600];

function formatIntervalLabel(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${seconds}s (${Math.floor(seconds / 60)} Min)`;
    return `${seconds}s (${Math.floor(seconds / 3600)} Std)`;
}

function populateIntervalSelect(selectId, allowedValues, currentValue) {
    const select = document.getElementById(selectId);
    if (!select) return;
    
    select.innerHTML = '';
    allowedValues.forEach(val => {
        const selected = (currentValue && parseInt(currentValue) === val) ? 'selected' : '';
        const label = formatIntervalLabel(val);
        select.innerHTML += `<option value="${val}" ${selected}>${label}</option>`;
    });
}

async function loadPublicIP() {
    const ipDisplay = document.getElementById('publicIpDisplay');
    const intervalSelect = document.getElementById('publicIpInterval');
    
    if (!ipDisplay) return;
    
    try {
        const response = await fetch('/api/v1/public-ip');
        if (response.ok) {
            const data = await response.json();
            
            ipDisplay.textContent = data.ip || 'Unbekannt';
            ipDisplay.className = 'ip-value ip-loaded';
            
            // Populate interval select if available
            if (intervalSelect) {
                const refreshInterval = data.refresh_interval || 600; // Default to 600s if not set
                populateIntervalSelect('publicIpInterval', allowedPublicIPIntervalValues, refreshInterval);
            }
            
            // Schedule next refresh
            const interval = data.refresh_interval || 600;
            if (publicIPIntervalTimer) {
                clearTimeout(publicIPIntervalTimer);
            }
            publicIPIntervalTimer = setTimeout(loadPublicIP, interval * 1000);
        } else {
            ipDisplay.textContent = 'Error';
            ipDisplay.className = 'ip-value ip-error';
            // Set default interval to 600s if API call fails
            if (intervalSelect) {
                populateIntervalSelect('publicIpInterval', allowedPublicIPIntervalValues, 600);
            }
        }
    } catch (error) {
        ipDisplay.textContent = 'Error';
        ipDisplay.className = 'ip-value ip-error';
        console.error('Error loading public IP:', error);
        // Set default interval to 600s on error
        if (intervalSelect) {
            populateIntervalSelect('publicIpInterval', allowedPublicIPIntervalValues, 600);
        }
    }
}

async function savePublicIPInterval() {
    const intervalSelect = document.getElementById('publicIpInterval');
    if (!intervalSelect) return;
    
    const interval = parseInt(intervalSelect.value);
    if (isNaN(interval) || !allowedPublicIPIntervalValues.includes(interval)) {
        showToast('Invalid interval', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/public-ip/refresh-interval', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({interval: interval})
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        // Reload IP with new interval
        if (publicIPIntervalTimer) {
            clearTimeout(publicIPIntervalTimer);
        }
        await loadPublicIP();
        
        showToast('Interval saved', 'success');
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving interval:', error);
    }
}

// Helper function to get token_id from zone element
function getTokenIdForZone(zoneId) {
    const zoneSection = document.querySelector(`.zone-section[data-token-id]`);
    if (zoneSection) {
        const zoneContent = zoneSection.querySelector(`#zone-content-${escapeHtml(zoneId)}`);
        if (zoneContent) {
            return zoneContent.getAttribute('data-token-id');
        }
        return zoneSection.getAttribute('data-token-id');
    }
    return null;
}

async function loadZoneRRSets(zoneId, zoneName, tokenId = null) {
    const zoneIdEscaped = escapeHtml(zoneId);
    const rrsetsDiv = document.getElementById(`rrsets-${zoneIdEscaped}`);
    if (!rrsetsDiv) return;
    
    // Get token_id from zone element if not provided
    if (!tokenId) {
        tokenId = getTokenIdForZone(zoneId);
    }
    
    try {
        const encodedZoneId = encodeURIComponent(zoneId);
        let url = `/api/v1/zones/${encodedZoneId}/rrsets`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url);
        if (!response.ok) {
            rrsetsDiv.innerHTML = `<p class="error">Error loading entries: ${response.status}</p>`;
            return;
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            rrsetsDiv.innerHTML = '<p class="error">Invalid response from server</p>';
            return;
        }
        
        const data = await response.json();
        const allRrsets = data.rrsets || [];
        
        // Filter out NS (Nameserver), SOA, MX, and TXT records - only show A and AAAA
        const rrsets = allRrsets.filter(rrset => {
            const type = rrset.type || '';
            return type === 'A' || type === 'AAAA';
        });
        
        // Button to create new A/AAAA records
        let tableHTML = `
            <div style="margin-bottom: 20px;">
                <button class="btn btn-primary" onclick="showCreateRecordDialog('${zoneId}', '${zoneName}', '${tokenId || ''}')" style="margin-bottom: 10px;">
                    + New A/AAAA Record
                </button>
            </div>
        `;
        
        if (rrsets.length === 0) {
            tableHTML += '<p style="color: #666; font-style: italic; padding: 10px;">Keine Einträge vorhanden</p>';
            rrsetsDiv.innerHTML = tableHTML;
            return;
        }
        
        // Hole Server-IP für Vergleich
        let serverIP = null;
        try {
            const ipResponse = await fetch('/api/v1/public-ip');
            if (ipResponse.ok) {
                const ipData = await ipResponse.json();
                serverIP = ipData.ip || null;
            }
        } catch (error) {
            console.error('Error loading server IP:', error);
        }
        
        // Erstelle Tabelle mit responsive Container
        tableHTML += '<div class="table-container" style="padding: 0 20px;"><table class="rrsets-table"><thead><tr>';
        tableHTML += '<th>Name</th>';
        tableHTML += '<th>Typ</th>';
        tableHTML += '<th>Auto-Update</th>';
        tableHTML += '<th>Monitor IP</th>';
        tableHTML += '<th>Status</th>';
        tableHTML += '<th>Public IP</th>';
        tableHTML += '<th>Current TTL</th>';
        tableHTML += '<th>TTL</th>';
        tableHTML += '<th>Comment</th>';
        tableHTML += '<th>Actions</th>';
        tableHTML += '</tr></thead><tbody>';
        
        for (const rrset of rrsets) {
            const records = rrset.records || [];
            const recordsDisplay = records.length > 0 ? records.map(r => escapeHtml(r)).join('<br>') : '-';
            const rrsetId = rrset.id || '';
            const rrsetIdEscaped = escapeHtml(rrsetId);
            const isIPRecord = rrset.type === 'A' || rrset.type === 'AAAA';
            // Die IP aus dem DNS-Record (nicht die Server-IP) - für A/AAAA Records
            const dnsRecordIP = records.length > 0 && isIPRecord ? records[0] : null;
            const autoUpdateEnabled = rrset.auto_update_enabled || false;
            // Use TTL override if explicitly set, otherwise use TTL from DNS record
            // If ttl_override is undefined (not set), use the current DNS record TTL
            // Backend only sets ttl_override if it exists, so undefined means "use DNS record TTL"
            const ttlValue = (rrset.ttl_override !== undefined && rrset.ttl_override !== null) 
                ? rrset.ttl_override 
                : (rrset.ttl || 3600);
            const existsInDNS = rrset.exists_in_dns !== false; // Default to true if not specified
            
            // Add red background class if record doesn't exist in DNS
            const rowClass = existsInDNS ? '' : 'deleted-record';
            
            // Get Monitor IP early (needed for Auto-Update check)
            const savedLocalIP = rrset.local_ip || '';
            
            tableHTML += `<tr data-rrset-id="${rrsetId}" data-zone-id="${zoneId}" class="${rowClass}">`;
            // Name
            tableHTML += `<td>${escapeHtml(rrset.name || 'N/A')}</td>`;
            
            // Typ
            tableHTML += `<td><span class="record-type">${escapeHtml(rrset.type || 'N/A')}</span></td>`;
            
            // Auto-Update Checkbox
            tableHTML += '<td class="auto-update-cell">';
            if (!existsInDNS) {
                tableHTML += '<span style="color: #dc3545;">✗ Nicht vorhanden</span>';
            } else if (isIPRecord) {
                if (autoUpdateEnabled && !savedLocalIP) {
                    // Auto-Update is enabled but Monitor IP is required
                    tableHTML += `<input type="checkbox" class="auto-update-checkbox" checked data-rrset-id="${rrsetId}" data-zone-id="${zoneId}" onchange="toggleAutoUpdate('${zoneId}', '${rrsetId}', this.checked)">`;
                    tableHTML += '<br><small style="color: #ff9800; display: block; margin-top: 5px;">Monitor IP is required</small>';
                } else {
                    tableHTML += `<input type="checkbox" class="auto-update-checkbox" ${autoUpdateEnabled ? 'checked' : ''} data-rrset-id="${rrsetId}" data-zone-id="${zoneId}" onchange="toggleAutoUpdate('${zoneId}', '${rrsetId}', this.checked)">`;
                }
            } else {
                tableHTML += '-';
            }
            tableHTML += '</td>';
            
            // Monitor IP Input
            tableHTML += '<td class="local-ip-cell">';
            if (!existsInDNS) {
                tableHTML += `<span style="color: #dc3545;">${escapeHtml(savedLocalIP || '-')}</span>`;
            } else {
                const savedPort = rrset.port || '';
                tableHTML += `<div style="display: flex; gap: 5px; align-items: stretch;">`;
                tableHTML += `<input type="text" class="local-ip-input" placeholder="e.g. 192.168.1.100" value="${escapeHtml(savedLocalIP)}" data-rrset-id="${rrsetId}" data-zone-id="${zoneId}" style="flex: 1;" onchange="saveLocalIPWithPort('${zoneId}', '${rrsetId}'); startAutomaticHealthChecks('${zoneId}');">`;
                tableHTML += `<input type="number" class="local-ip-port-input" placeholder="Port" value="${escapeHtml(savedPort)}" data-rrset-id="${rrsetId}" data-zone-id="${zoneId}" min="1" max="65535" style="width: 100px;" onchange="saveLocalIPWithPort('${zoneId}', '${rrsetId}'); startAutomaticHealthChecks('${zoneId}');">`;
                tableHTML += `</div>`;
            }
            tableHTML += '</td>';
            
            // Status display
            tableHTML += '<td class="ip-status-cell">';
            if (!existsInDNS) {
                tableHTML += '<span style="color: #dc3545;">✗ Record deleted</span>';
            } else {
                tableHTML += `<span class="ip-status" id="status-${rrsetId}" data-ip="">-</span>`;
            }
            tableHTML += '</td>';
            
            // Display DNS record values from Hetzner DNS (editable for A/AAAA records)
            tableHTML += '<td class="public-ip-cell">';
            if (!existsInDNS) {
                tableHTML += '<span style="color: #dc3545;">-</span>';
            } else if (isIPRecord && records.length > 0) {
                // For A/AAAA records: Editable input field
                const currentIP = records[0] || '';
                let ipClass = 'public-ip-input';
                if (serverIP && currentIP === serverIP) {
                    ipClass += ' ip-match';
                }
                tableHTML += `<input type="text" class="${ipClass}" placeholder="IP Address" value="${escapeHtml(currentIP)}" data-rrset-id="${rrsetIdEscaped}" data-zone-id="${zoneIdEscaped}" data-record-type="${escapeHtml(rrset.type)}" onchange="savePublicIPForRecord('${zoneId}', '${rrsetId.replace(/'/g, "\\'")}', this.value)" style="width: 100%; padding: 4px; border: 1px solid #ddd; border-radius: 4px;">`;
            } else if (records.length > 0) {
                // For other record types: Display only
                tableHTML += `<span class="public-ip-value">${recordsDisplay}</span>`;
            } else {
                tableHTML += '<span class="public-ip-value">-</span>';
            }
            tableHTML += '</td>';
            
            // Display current TTL from Hetzner API
            const currentTTL = rrset.ttl || null;
            tableHTML += '<td class="current-ttl-cell">';
            if (!existsInDNS) {
                tableHTML += '<span style="color: #dc3545;">-</span>';
            } else if (currentTTL !== null) {
                tableHTML += `<span class="current-ttl-value">${currentTTL}s</span>`;
            } else {
                tableHTML += '<span class="current-ttl-value">-</span>';
            }
            tableHTML += '</td>';
            
            // TTL Input
            tableHTML += '<td class="ttl-cell">';
            if (!existsInDNS) {
                tableHTML += `<span style="color: #dc3545;">${ttlValue ? ttlValue + 's' : '-'}</span>`;
            } else {
                const allowedTTLValues = [60, 300, 600, 1800, 3600, 86400];
                const currentTTL = ttlValue ? parseInt(ttlValue) : 3600;
                const ttlOptions = allowedTTLValues.map(val => {
                    const selected = (currentTTL === val) ? 'selected' : '';
                    const label = `${val}s`;
                    return `<option value="${val}" ${selected}>${label}</option>`;
                }).join('');
                // If current TTL is not in allowed values, add it as an option
                let customTTLOption = '';
                if (currentTTL && !allowedTTLValues.includes(currentTTL)) {
                    customTTLOption = `<option value="${currentTTL}" selected>${currentTTL}s (Custom)</option>`;
                }
                tableHTML += `<select class="ttl-input" data-rrset-id="${rrsetIdEscaped}" data-zone-id="${zoneIdEscaped}" onchange="saveTTL('${zoneId}', '${rrsetId.replace(/'/g, "\\'")}', this.value)" style="width: 100%; padding: 4px; border: 1px solid #ddd; border-radius: 4px;">${customTTLOption}${ttlOptions}</select>`;
            }
            tableHTML += '</td>';
            
            // Comment input
            const commentValue = rrset.comment || '';
            tableHTML += '<td class="comment-cell">';
            if (!existsInDNS) {
                tableHTML += `<span style="color: #dc3545;">${escapeHtml(commentValue || '-')}</span>`;
            } else {
                tableHTML += `<input type="text" class="comment-input" placeholder="Comment (optional)" value="${escapeHtml(commentValue)}" data-rrset-id="${rrsetIdEscaped}" data-zone-id="${zoneIdEscaped}" onchange="saveComment('${zoneId}', '${rrsetId.replace(/'/g, "\\'")}', this.value)" style="width: 100%; padding: 4px; border: 1px solid #ddd; border-radius: 4px;">`;
            }
            tableHTML += '</td>';
            
            // Actions
            tableHTML += '<td class="actions-cell">';
            if (!existsInDNS) {
                // Show delete button for deleted records
                tableHTML += `<button id="delete-settings-btn-${rrsetId}" class="btn btn-small btn-danger" onclick="deleteRRSetSettings('${zoneId}', '${rrsetId}')" title="Delete Settings">Delete Settings</button>`;
            } else {
                // Show action buttons for existing records
                let actionButtons = '';
                // Add edit button for all records
                const recordName = rrset.name || '@';
                const recordType = rrset.type || '';
                const recordNameEscaped = escapeHtml(recordName);
                const recordTypeEscaped = escapeHtml(recordType);
                const zoneIdEscapedForRecord = escapeHtml(zoneId);
                const rrsetIdEscaped = escapeHtml(rrsetId);
                const currentRecords = records.length > 0 ? records.join(',') : '';
                const currentTTL = rrset.ttl || 3600;
                actionButtons += `<button id="edit-btn-${rrsetIdEscaped}" class="btn btn-small btn-secondary" data-zone-id="${zoneIdEscapedForRecord}" data-rrset-id="${rrsetIdEscaped}" data-record-name="${recordNameEscaped}" data-record-type="${recordTypeEscaped}" data-records="${escapeHtml(currentRecords)}" data-ttl="${currentTTL}" onclick="showEditRecordDialog(this.dataset.zoneId, this.dataset.rrsetId, this.dataset.recordName, this.dataset.recordType, this.dataset.records, this.dataset.ttl)" title="Edit Record" style="margin-right: 5px;">Edit</button>`;
                if (isIPRecord) {
                    actionButtons += `<button id="assign-btn-${rrsetId}" class="btn btn-small btn-primary" onclick="assignServerIP('${zoneId}', '${rrsetId}')" title="Assign Server IP" style="margin-right: 5px;">Assign IP</button>`;
                }
                // Add delete button for all records
                actionButtons += `<button id="delete-btn-${rrsetIdEscaped}" class="btn btn-small btn-danger" data-zone-id="${zoneIdEscapedForRecord}" data-rrset-id="${rrsetIdEscaped}" data-record-name="${recordNameEscaped}" data-record-type="${recordTypeEscaped}" onclick="showDeleteRecordDialog(this.dataset.zoneId, this.dataset.rrsetId, this.dataset.recordName, this.dataset.recordType)" title="Delete Record">Delete</button>`;
                tableHTML += actionButtons || '-';
            }
            tableHTML += '</td>';
            
            tableHTML += '</tr>';
        }
        
        tableHTML += '</tbody></table></div>';
        rrsetsDiv.innerHTML = tableHTML;
        
        // Automatically expand zone after loading
        const zoneContent = document.getElementById(`zone-content-${zoneIdEscaped}`);
        if (zoneContent) {
            zoneContent.classList.remove('collapsed');
            zoneContent.classList.add('expanded');
            const toggleIcon = document.getElementById(`toggle-icon-${zoneIdEscaped}`);
            if (toggleIcon) toggleIcon.textContent = '▼';
        }
        
        // Stop existing health checks before starting new ones
        stopAutomaticHealthChecks(zoneId);
        
        // Start automatic health checks for entries with local IPs
        // Use setTimeout to ensure DOM is ready and prevent multiple calls
        setTimeout(() => {
            // Double-check that timers are still cleared (prevent race conditions)
            if (!healthCheckTimers[zoneId]) {
                startAutomaticHealthChecks(zoneId);
            }
        }, 200);
        
    } catch (error) {
        rrsetsDiv.innerHTML = `<p class="error">Error loading entries: ${error.message}</p>`;
        console.error('Error loading RRSets:', error);
    }
}

// Store timers for automatic health checks
const healthCheckTimers = {};
let localIPStatusInterval = 600; // Default 600 seconds (10 minutes)


// Load local IP status interval from localStorage or use default
function loadLocalIPStatusInterval() {
    const saved = localStorage.getItem('localIPStatusInterval');
    if (saved) {
        localIPStatusInterval = parseInt(saved, 10);
        populateIntervalSelect('localIpStatusInterval', allowedMonitorIPIntervalValues, localIPStatusInterval);
    } else {
        populateIntervalSelect('localIpStatusInterval', allowedMonitorIPIntervalValues, 600);
    }
}

async function saveLocalIPStatusInterval() {
    const intervalSelect = document.getElementById('localIpStatusInterval');
    if (!intervalSelect) return;
    
    const interval = parseInt(intervalSelect.value, 10);
    
    if (isNaN(interval) || !allowedMonitorIPIntervalValues.includes(interval)) {
        showToast('Invalid interval', 'error');
        return;
    }
    
    try {
        localStorage.setItem('localIPStatusInterval', interval.toString());
        localIPStatusInterval = interval;
        
        // Restart health checks with new interval
        const zoneSections = document.querySelectorAll('[id^="rrsets-"]');
        zoneSections.forEach(div => {
            const zoneId = div.id.replace('rrsets-', '');
            if (zoneId) {
                stopAutomaticHealthChecks(zoneId);
                startAutomaticHealthChecks(zoneId);
            }
        });
        
        showToast('Interval saved', 'success');
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving interval:', error);
    }
}

// Load auto-update interval from server
async function loadAutoUpdateInterval() {
    const intervalSelect = document.getElementById('autoUpdateInterval');
    
    try {
        const response = await fetch('/api/v1/auto-update/interval');
        if (response.ok) {
            const data = await response.json();
            const interval = data.interval || 600;
            populateIntervalSelect('autoUpdateInterval', allowedAutoUpdateIntervalValues, interval);
        } else {
            // Use default if API call fails
            populateIntervalSelect('autoUpdateInterval', allowedAutoUpdateIntervalValues, 600);
        }
    } catch (error) {
        console.error('Error loading auto-update interval:', error);
        // Use default on error
        populateIntervalSelect('autoUpdateInterval', allowedAutoUpdateIntervalValues, 600);
    }
}

async function saveAutoUpdateInterval() {
    const intervalSelect = document.getElementById('autoUpdateInterval');
    if (!intervalSelect) return;
    
    const interval = parseInt(intervalSelect.value, 10);
    if (isNaN(interval) || !allowedAutoUpdateIntervalValues.includes(interval)) {
        showToast('Invalid interval', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/auto-update/interval', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({interval: interval})
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        showToast('Interval saved', 'success');
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving auto-update interval:', error);
    }
}

function startAutomaticHealthChecks(zoneId) {
    // Clear existing timers for this zone (double-check)
    if (healthCheckTimers[zoneId]) {
        healthCheckTimers[zoneId].forEach(timer => {
            clearInterval(timer);
        });
        delete healthCheckTimers[zoneId];
    }
    
    // Ensure interval is at least 5 seconds to prevent too frequent requests
    const minInterval = Math.max(localIPStatusInterval, 5);
    
    healthCheckTimers[zoneId] = [];
    
    // Find all rows with local IP inputs
    const rows = document.querySelectorAll(`tr[data-zone-id="${zoneId}"]`);
    
    rows.forEach(row => {
        const rrsetId = row.getAttribute('data-rrset-id');
        const localIpInput = row.querySelector('.local-ip-input');
        const statusSpan = document.getElementById(`status-${rrsetId}`);
        
        if (!localIpInput || !statusSpan) return;
        
        const localIP = localIpInput.value.trim();
        
        // Only check if local IP is set
        if (!localIP) {
            statusSpan.textContent = '✗ Not reachable';
            statusSpan.className = 'ip-status error';
            return;
        }
        
        // Check immediately
        checkIPStatus(zoneId, rrsetId);
        
        // Then check at configured interval (minimum 5 seconds)
        const timer = setInterval(() => {
            checkIPStatus(zoneId, rrsetId);
        }, minInterval * 1000);
        
        healthCheckTimers[zoneId].push(timer);
    });
}

function stopAutomaticHealthChecks(zoneId) {
    if (healthCheckTimers[zoneId]) {
        healthCheckTimers[zoneId].forEach(timer => {
            clearInterval(timer);
        });
        delete healthCheckTimers[zoneId];
    }
}

// Stop all health checks (called when switching tabs or reloading)
function stopAllHealthChecks() {
    Object.keys(healthCheckTimers).forEach(zoneId => {
        stopAutomaticHealthChecks(zoneId);
    });
}

async function deleteRRSetSettings(zoneId, rrsetId) {
    if (!confirm('Do you really want to delete all settings for this record? (Monitor IP, Auto-Update, TTL)')) {
        return;
    }
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/settings`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        showToast('Settings successfully deleted', 'success');
        
        // Reload RRSets to update the table
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error deleting: ' + error.message, 'error');
        console.error('Error deleting RRSet settings:', error);
    }
}

async function assignServerIP(zoneId, rrsetId) {
    if (!confirm('Do you want to assign the current public IP of the server to this entry?')) {
        return;
    }
    
    // Find button and show loading state
    const button = document.getElementById(`assign-btn-${rrsetId}`);
    const originalText = button ? button.textContent : 'Assign IP';
    const originalDisabled = button ? button.disabled : false;
    
    if (button) {
        button.disabled = true;
        button.textContent = 'Assigning...';
        button.style.opacity = '0.6';
        button.style.cursor = 'wait';
    }
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/assign-server-ip`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            
            // Reset button state on error
            if (button) {
                button.disabled = originalDisabled;
                button.textContent = originalText;
                button.style.opacity = '1';
                button.style.cursor = 'pointer';
            }
            return;
        }
        
        const data = await response.json();
        showToast(`IP ${data.assigned_ip} successfully assigned!`, 'success');
        
        // Reload RRSets (this will recreate the button, so no need to reset it)
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error assigning IP: ' + error.message, 'error');
        console.error('Error assigning server IP:', error);
        
        // Reset button state on error
        if (button) {
            button.disabled = originalDisabled;
            button.textContent = originalText;
            button.style.opacity = '1';
            button.style.cursor = 'pointer';
        }
    }
}

async function saveLocalIP(zoneId, rrsetId, localIP) {
    // Legacy function - redirect to new function with port
    const row = document.querySelector(`tr[data-rrset-id="${rrsetId}"]`);
    if (row) {
        const portInput = row.querySelector('.local-ip-port-input');
        const port = portInput ? (portInput.value ? parseInt(portInput.value) : null) : null;
        await saveLocalIPWithPort(zoneId, rrsetId, localIP, port);
    } else {
        await saveLocalIPWithPort(zoneId, rrsetId, localIP, null);
    }
}

async function saveLocalIPWithPort(zoneId, rrsetId, localIP = null, port = null) {
    const row = document.querySelector(`tr[data-rrset-id="${rrsetId}"]`);
    if (!row) return;
    
    const ipInput = row.querySelector('.local-ip-input');
    const portInput = row.querySelector('.local-ip-port-input');
    
    const ip = localIP !== null ? localIP.trim() : (ipInput ? ipInput.value.trim() : '');
    const portValue = port !== null ? port : (portInput ? (portInput.value ? parseInt(portInput.value) : null) : null);
    
    if (!ip || !ip.trim()) {
        // Empty IP - delete it
        try {
            const tokenId = getTokenIdForZone(zoneId);
            let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/local-ip`;
            if (tokenId) {
                url += `?token_id=${encodeURIComponent(tokenId)}`;
            }
            const response = await fetch(url, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                showToast('Monitor IP deleted', 'success');
                if (ipInput) ipInput.value = '';
                if (portInput) portInput.value = '';
            }
        } catch (error) {
            console.error('Error deleting local IP:', error);
        }
        return;
    }
    
    // Validate IP format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(ip)) {
        showToast('Invalid IP format', 'error');
        // Reset input to previous value
        if (ipInput) {
            ipInput.value = ipInput.getAttribute('data-saved-value') || '';
        }
        return;
    }
    
    // Validate port if provided
    if (portValue !== null && (portValue < 1 || portValue > 65535)) {
        showToast('Invalid port (must be 1-65535)', 'error');
        if (portInput) {
            portInput.value = portInput.getAttribute('data-saved-port') || '';
        }
        return;
    }
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/local-ip`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                local_ip: ip,
                port: portValue
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error saving: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        const data = await response.json();
        
        // Save current values as saved values
        if (ipInput) {
            ipInput.setAttribute('data-saved-value', ip);
        }
        if (portInput) {
            portInput.setAttribute('data-saved-port', portValue || '');
        }
        
        showToast('Monitor IP saved', 'success');
        
        // Restart automatic health checks
        startAutomaticHealthChecks(zoneId);
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving local IP:', error);
    }
}

async function checkIPStatus(zoneId, rrsetId) {
    const row = document.querySelector(`tr[data-rrset-id="${rrsetId}"]`);
    if (!row) return;
    
    const localIpInput = row.querySelector('.local-ip-input');
    const localPortInput = row.querySelector('.local-ip-port-input');
    const statusSpan = document.getElementById(`status-${rrsetId}`);
    
    if (!localIpInput || !statusSpan) return;
    
    const ip = localIpInput.value.trim();
    const port = localPortInput ? (localPortInput.value ? parseInt(localPortInput.value) : null) : null;
    
    // If no IP is set, show "nicht erreichbar" and return
    if (!ip) {
        statusSpan.textContent = '✗ Nicht erreichbar';
        statusSpan.className = 'ip-status error';
        statusSpan.removeAttribute('data-ip');
        return;
    }
    
    // Validate IP format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(ip)) {
        statusSpan.textContent = 'Invalid';
        statusSpan.className = 'ip-status error';
        return;
    }
    
        statusSpan.textContent = 'Checking...';
    statusSpan.className = 'ip-status checking';
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/check-ip`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ip: ip,
                port: port,
                check_method: 'ping',
                timeout: 5
            })
        });
        
        if (!response.ok) {
            statusSpan.textContent = 'Error';
            statusSpan.className = 'ip-status error';
            return;
        }
        
        const data = await response.json();
        const previousStatus = statusSpan.getAttribute('data-reachable') === 'true';
        statusSpan.setAttribute('data-ip', ip);
        statusSpan.setAttribute('data-reachable', data.reachable ? 'true' : 'false');
        
        if (data.reachable) {
            statusSpan.textContent = '✓ Alive';
            statusSpan.className = 'ip-status alive';
            if (data.response_time) {
                statusSpan.title = `Response Time: ${(data.response_time * 1000).toFixed(0)}ms`;
            }
        } else {
            statusSpan.textContent = '✗ Dead';
            statusSpan.className = 'ip-status dead';
            
            // Log offline event if IP was previously online
            if (previousStatus) {
                // Send notification to backend
                const tokenId = getTokenIdForZone(zoneId);
                let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/check-ip`;
                if (tokenId) {
                    url += `?token_id=${encodeURIComponent(tokenId)}`;
                }
                // Send with previous_status parameter
                fetch(url, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        ip: ip,
                        port: port,
                        check_method: 'ping',
                        timeout: 5,
                        previous_status: true
                    })
                }).catch(err => console.error('Error logging monitor IP offline:', err));
            }
        }
        
    } catch (error) {
        statusSpan.textContent = 'Error';
        statusSpan.className = 'ip-status error';
        console.error('Error checking IP status:', error);
    }
}

async function toggleAutoUpdate(zoneId, rrsetId, enabled) {
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${rrsetId}/auto-update`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                enabled: enabled
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            // Reset checkbox
            const checkbox = document.querySelector(`input[data-rrset-id="${rrsetId}"].auto-update-checkbox`);
            if (checkbox) {
                checkbox.checked = !enabled;
            }
            return;
        }
        
        showToast(enabled ? 'Auto-Update aktiviert' : 'Auto-Update deaktiviert', 'success');
        
        // Reload RRSets to show updated state (e.g., "Monitor IP ist erforderlich" message)
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error setting auto-update: ' + error.message, 'error');
        console.error('Error toggling auto-update:', error);
        // Reset checkbox
        const checkbox = document.querySelector(`input[data-rrset-id="${rrsetId}"].auto-update-checkbox`);
        if (checkbox) {
            checkbox.checked = !enabled;
        }
    }
}

async function saveTTL(zoneId, rrsetId, ttlValue) {
    const allowedTTLValues = [60, 300, 600, 1800, 3600, 86400];
    const ttl = ttlValue === '' || ttlValue === null ? null : parseInt(ttlValue);
    
    if (ttl !== null && !allowedTTLValues.includes(ttl)) {
        showToast('TTL must be one of the allowed values: 60, 300, 600, 1800, 3600, 86400 seconds', 'error');
        // Reset select
        const select = document.querySelector(`select[data-rrset-id="${rrsetId}"].ttl-input`);
        if (select) {
            select.value = select.getAttribute('data-saved-ttl') || '3600';
        }
        return;
    }
    
    try {
        const encodedZoneId = encodeURIComponent(zoneId);
        const encodedRrsetId = encodeURIComponent(rrsetId);
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${encodedZoneId}/rrsets/${encodedRrsetId}/ttl`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ttl: ttl
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        const data = await response.json();
        
        // Save current value as saved value
        const select = document.querySelector(`select[data-rrset-id="${rrsetId}"].ttl-input`);
        if (select) {
            select.setAttribute('data-saved-ttl', ttl || '');
        }
        
        showToast('TTL saved', 'success');
        
        // Reload RRSets to show updated TTL
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving TTL:', error);
    }
}

async function saveComment(zoneId, rrsetId, commentValue) {
    const comment = commentValue === '' || commentValue === null ? null : commentValue.trim();
    
    try {
        const encodedZoneId = encodeURIComponent(zoneId);
        const encodedRrsetId = encodeURIComponent(rrsetId);
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${encodedZoneId}/rrsets/${encodedRrsetId}/comment`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                comment: comment
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            return;
        }
        
        const data = await response.json();
        
        showToast('Comment saved', 'success');
        
        // Reload RRSets to show updated comment
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving comment:', error);
    }
}

async function savePublicIPForRecord(zoneId, rrsetId, ipValue) {
    const ip = ipValue.trim();
    
    // Validate IP format
    if (ip) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        
        if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            showToast('Invalid IP format', 'error');
            // Reload to reset input
            const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
            await loadZoneRRSets(zoneId, zoneName);
            return;
        }
    } else {
        showToast('IP address cannot be empty', 'error');
        // Reload to reset input
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        return;
    }
    
    try {
        const encodedZoneId = encodeURIComponent(zoneId);
        const encodedRrsetId = encodeURIComponent(rrsetId);
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${encodedZoneId}/rrsets/${encodedRrsetId}/ip`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ip: ip
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            // Reload to reset input
            const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
            await loadZoneRRSets(zoneId, zoneName);
            return;
        }
        
        const data = await response.json();
        
        showToast('IP address saved', 'success');
        
        // Reload RRSets to show updated IP
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
        console.error('Error saving IP:', error);
        // Reload to reset input
        const zoneName = document.querySelector(`[data-zone-id="${zoneId}"]`)?.closest('.zone-section')?.querySelector('h3')?.textContent || '';
        await loadZoneRRSets(zoneId, zoneName);
    }
}

function viewZoneDetails(zoneId, zoneName) {
    alert(`Zone Details for: ${zoneName}\nZone ID: ${zoneId}\n\nThis feature is not yet implemented.`);
}

async function loadApiTokens() {
    try {
        const response = await fetch('/api/v1/config/api-tokens');
        if (!response.ok) {
            console.error('Failed to load API tokens:', response.status, response.statusText);
            return;
        }
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            console.error('Response is not JSON:', contentType);
            return;
        }
        const data = await response.json();
        
        // Display saved tokens
        displaySavedTokens(data);
    } catch (error) {
        console.error('Error loading API tokens:', error);
    }
}

async function loadMachineName() {
    try {
        const response = await fetch('/api/v1/config/machine-name');
        if (!response.ok) {
            console.error('Failed to load machine name:', response.status);
            return;
        }
        const data = await response.json();
        const machineNameInput = document.getElementById('machineNameInput');
        if (machineNameInput) {
            machineNameInput.value = data.machine_name || '';
        }
    } catch (error) {
        console.error('Error loading machine name:', error);
    }
}

async function saveMachineName() {
    const machineNameInput = document.getElementById('machineNameInput');
    if (!machineNameInput) return;
    
    const machineName = machineNameInput.value.trim();
    const saveBtn = document.getElementById('saveMachineNameBtn');
    const originalText = saveBtn ? saveBtn.textContent : '';
    
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
    }
    
    try {
        const response = await fetch('/api/v1/config/machine-name', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ machine_name: machineName })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.textContent = originalText;
            }
            return;
        }
        
        showToast('Machine name saved', 'success');
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = originalText;
        }
    }
}

function displaySavedTokens(data) {
    const savedTokensDiv = document.getElementById('savedTokens');
    if (!savedTokensDiv) return;
    
    // Use new tokens array if available, otherwise fall back to old format
    const tokens = data.tokens || [];
    
    // Also include new_api format tokens for backward compatibility
    if (data.new_api && data.new_api.token_set) {
        const newTokenExists = tokens.some(t => t.type === 'new');
        if (!newTokenExists) {
            tokens.push({
                id: 'new',
                name: data.new_api.name || 'New Hetzner Console Token',
                masked_token: data.new_api.masked_token || '***',
                type: 'new',
                base_url: data.new_api.base_url || 'https://api.hetzner.cloud/v1'
            });
        }
    }
    
    if (tokens.length === 0) {
        savedTokensDiv.innerHTML = '<p style="color: #666; font-style: italic;">No tokens saved</p>';
        return;
    }
    
    savedTokensDiv.innerHTML = '<h3>Saved Tokens</h3>' + tokens.map(token => {
        const typeLabel = 'New Hetzner Console';
        return `
        <div class="saved-token-item" style="display: flex; justify-content: space-between; align-items: center; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px;">
            <div class="saved-token-info" style="flex: 1;">
                <div style="font-weight: bold; margin-bottom: 5px;">${escapeHtml(token.name)}</div>
                <div style="font-family: monospace; color: #666; font-size: 0.9em; margin-bottom: 3px;">${escapeHtml(token.masked_token)}</div>
                <div style="margin-top: 5px;">
                    <span style="font-size: 0.85em; color: #999; background: #f0f0f0; padding: 2px 6px; border-radius: 3px; margin-right: 5px;">${escapeHtml(typeLabel)}</span>
                    <span style="font-size: 0.75em; color: #666; font-family: monospace; background: #e8f4f8; padding: 2px 6px; border-radius: 3px;" title="Token ID">ID: ${escapeHtml(token.id)}</span>
                </div>
            </div>
            <button class="btn btn-secondary" onclick="deleteTokenById('${token.id}')" style="margin-left: 10px; padding: 5px 10px;">Delete</button>
        </div>
    `;
    }).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function deleteTokenById(tokenId) {
    if (!confirm(`Do you really want to delete this token?`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/v1/config/api-tokens/${tokenId}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            showToast('Error deleting token: ' + response.status + ' ' + response.statusText, 'error');
            console.error('Delete token error:', errorText);
            return;
        }
        
        showToast('Token deleted successfully', 'success');
        loadApiTokens();
    } catch (error) {
        showToast('Error deleting token: ' + error.message, 'error');
        console.error('Delete token error:', error);
    }
}

async function deleteToken(apiType) {
    // Legacy function for backward compatibility
    await deleteTokenById(apiType);
}

async function addNewToken() {
    const nameInput = document.getElementById('newTokenNameInput');
    const tokenInput = document.getElementById('newTokenInput');
    
    if (!nameInput || !tokenInput) {
        showToast('Form elements not found', 'error');
        return;
    }
    
    const name = nameInput.value.trim();
    const token = tokenInput.value.trim();
    
    if (!name) {
        showToast('Please enter a token name', 'error');
        return;
    }
    
    if (!token) {
        showToast('Please enter an API token', 'error');
        return;
    }
    
    try {
        const requestBody = {
            token: token,
            name: name,
            type: 'new'
        };
        
        const response = await fetch('/api/v1/config/api-tokens', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            let errorMessage = response.status + ' ' + response.statusText;
            try {
                const errorData = await response.json();
                if (errorData.detail) {
                    errorMessage = errorData.detail;
                }
            } catch (e) {
                const errorText = await response.text();
                if (errorText) {
                    try {
                        const errorJson = JSON.parse(errorText);
                        if (errorJson.detail) {
                            errorMessage = errorJson.detail;
                        }
                    } catch (e2) {
                        // Use default error message
                    }
                }
            }
            showToast('Error adding token: ' + errorMessage, 'error');
            console.error('Add token error:', errorMessage);
            return;
        }
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Token added successfully', 'success');
            
            // Clear form
            nameInput.value = '';
            tokenInput.value = '';
            
            // Reload tokens
            loadApiTokens();
        } else {
            showToast('Error adding token: ' + (data.message || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Error adding token: ' + error.message, 'error');
        console.error('Add token error:', error);
    }
}

// Legacy function removed - use addNewToken() instead
async function saveApiTokens() {
    showToast('Please use "Add New API Token" form instead', 'info');
}

async function testApiTokens() {
    const oldTokenInput = document.getElementById('oldToken');
    const newTokenInput = document.getElementById('newToken');
    const oldToken = oldTokenInput ? oldTokenInput.value.trim() : '';
    const newToken = newTokenInput ? newTokenInput.value.trim() : '';
    
    try {
        const requestBody = {};
        if (oldToken) {
            requestBody.old_token = oldToken;
        }
        if (newToken) {
            requestBody.new_token = newToken;
        }
        
        const response = await fetch('/api/v1/config/test-api-tokens', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            showToast('Error testing: ' + response.status, 'error');
            console.error('Test tokens error:', errorText);
            return;
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            showToast('Ungültige Antwort vom Server', 'error');
            console.error('Response is not JSON:', contentType, text);
            return;
        }
        
        const data = await response.json();
        
        const oldTokenStatus = document.getElementById('oldTokenStatus');
        const newTokenStatus = document.getElementById('newTokenStatus');
        
        let testedCount = 0;
        let validCount = 0;
        
        // Nur Status für getestete Token anzeigen
        if (oldToken && oldTokenStatus) {
            testedCount++;
            if (data.old_api.valid) {
                oldTokenStatus.textContent = '✓ Token valid';
                oldTokenStatus.className = 'token-status valid';
                validCount++;
            } else {
                oldTokenStatus.textContent = '✗ Token invalid: ' + data.old_api.message;
                oldTokenStatus.className = 'token-status invalid';
            }
        } else if (oldTokenStatus && !oldToken) {
            // Token nicht eingegeben, Status zurücksetzen
            oldTokenStatus.textContent = '';
            oldTokenStatus.className = 'token-status';
        }
        
        if (newToken && newTokenStatus) {
            testedCount++;
            if (data.new_api.valid) {
                newTokenStatus.textContent = '✓ Token valid';
                newTokenStatus.className = 'token-status valid';
                validCount++;
            } else {
                newTokenStatus.textContent = '✗ Token invalid: ' + data.new_api.message;
                newTokenStatus.className = 'token-status invalid';
            }
        } else if (newTokenStatus && !newToken) {
            // Token nicht eingegeben, Status zurücksetzen
            newTokenStatus.textContent = '';
            newTokenStatus.className = 'token-status';
        }
        
        // Toast-Nachricht basierend auf getesteten Tokens
        if (testedCount === 0) {
            showToast('Please enter at least one token to test', 'error');
        } else if (validCount === testedCount) {
            showToast('All tested tokens are valid', 'success');
        } else if (validCount > 0) {
            showToast(`${validCount} of ${testedCount} token(s) are valid`, 'info');
        } else {
            showToast('No token is valid', 'error');
        }
        
        // Update token display after successful test
        if (validCount > 0) {
            loadApiTokens();
        }
    } catch (error) {
        showToast('Error testing: ' + error.message, 'error');
    }
}


async function showCreateRecordDialog(zoneId, zoneName, tokenId = null) {
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    // Get public IP to pre-fill
    let publicIP = '';
    try {
        const ipResponse = await fetch('/api/v1/public-ip');
        if (ipResponse.ok) {
            const ipData = await ipResponse.json();
            publicIP = ipData.ip || '';
        }
    } catch (error) {
        console.log('Could not fetch public IP:', error);
    }
    
    dialog.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="margin-top: 0;">Create New A/AAAA Record</h2>
            <p style="color: #666; margin-bottom: 20px;">Zone: ${escapeHtml(zoneName)}</p>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Name:</label>
                <input type="text" id="newRecordName" placeholder="e.g. test or @ for root" value="" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666;">Leave empty or @ for root domain</small>
            </div>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Type:</label>
                <select id="newRecordType" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    <option value="A" ${publicIP ? 'selected' : ''}>A (IPv4)</option>
                    <option value="AAAA" ${!publicIP ? 'selected' : ''}>AAAA (IPv6)</option>
                </select>
            </div>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">IP Address:</label>
                <input type="text" id="newRecordIP" placeholder="e.g. 192.168.1.1 or 2001:db8::1" value="${escapeHtml(publicIP)}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                ${publicIP ? '<small style="color: #666; display: block; margin-top: 5px;">Public server IP was automatically entered (can be changed)</small>' : ''}
            </div>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">TTL (seconds):</label>
                <select id="newRecordTTL" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    <option value="60">60s</option>
                    <option value="300">300s</option>
                    <option value="600">600s</option>
                    <option value="1800">1800s</option>
                    <option value="3600" selected>3600s</option>
                    <option value="86400">86400s</option>
                </select>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('.modal-overlay').remove()" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                <button onclick="createRecord('${zoneId}', '${zoneName}')" class="btn btn-primary" style="padding: 10px 20px;">Create</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Close on overlay click
    dialog.addEventListener('click', function(e) {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
    
    // Focus on name input
    setTimeout(() => {
        const nameInput = document.getElementById('newRecordName');
        if (nameInput) {
            nameInput.focus();
        }
    }, 100);
}

async function createRecord(zoneId, zoneName, tokenId = null) {
    const nameInput = document.getElementById('newRecordName');
    const typeInput = document.getElementById('newRecordType');
    const ipInput = document.getElementById('newRecordIP');
    const ttlInput = document.getElementById('newRecordTTL');
    
    const name = nameInput.value.trim() || '@';
    const type = typeInput.value;
    const ip = ipInput.value.trim();
    const ttl = parseInt(ttlInput.value) || 3600;
    
    // Validation
    if (!ip) {
        showToast('Please enter an IP address', 'error');
        return;
    }
    
    // Basic IP validation
    if (type === 'A') {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Regex.test(ip)) {
            showToast('Invalid IPv4 address', 'error');
            return;
        }
    } else if (type === 'AAAA') {
        const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        if (!ipv6Regex.test(ip)) {
            showToast('Invalid IPv6 address', 'error');
            return;
        }
    }
    
    // Validate TTL against allowed values
    const allowedTTLValues = [60, 300, 600, 1800, 3600, 86400];
    if (!allowedTTLValues.includes(ttl)) {
        showToast('TTL must be one of the allowed values: 60, 300, 600, 1800, 3600, 86400 seconds', 'error');
        return;
    }
    
    // Save scroll position and zone state before creating record
    const savedScrollPosition = window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0;
    const zoneIdEscaped = escapeHtml(zoneId);
    const zoneContentDiv = document.getElementById(`zone-content-${zoneIdEscaped}`);
    const wasZoneOpen = zoneContentDiv && !zoneContentDiv.classList.contains('collapsed');
    
    // Disable button
    const createBtn = event.target;
    const originalText = createBtn.textContent;
    createBtn.disabled = true;
    createBtn.textContent = 'Erstelle...';
    
    // Get token_id if not provided
    if (!tokenId) {
        tokenId = getTokenIdForZone(zoneId);
    }
    
    try {
        let url = `/api/v1/zones/${zoneId}/rrsets`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                type: type,
                records: [ip],
                ttl: ttl
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            createBtn.disabled = false;
            createBtn.textContent = originalText;
            return;
        }
        
        const data = await response.json();
        showToast('Record successfully created', 'success');
        
        // Close dialog
        const dialog = document.querySelector('.modal-overlay');
        if (dialog) {
            dialog.remove();
        }
        
        // Reload zones to show new record
        await refreshZones();
        
        // Restore zone state and scroll position after DOM update
        // Wait a bit for the DOM to be fully rendered
        setTimeout(() => {
            // Open the zone if it was open before or if we just created a record
            const newZoneContentDiv = document.getElementById(`zone-content-${zoneIdEscaped}`);
            if (newZoneContentDiv && (wasZoneOpen || true)) {
                // Ensure zone is open
                if (newZoneContentDiv.classList.contains('collapsed')) {
                    newZoneContentDiv.classList.remove('collapsed');
                    newZoneContentDiv.classList.add('expanded');
                    const toggleIcon = document.getElementById(`toggle-icon-${zoneIdEscaped}`);
                    if (toggleIcon) toggleIcon.textContent = '▼';
                }
            }
            
            // Restore scroll position
            window.scrollTo({
                top: savedScrollPosition,
                behavior: 'instant'
            });
        }, 200);
        
    } catch (error) {
        showToast('Error creating: ' + error.message, 'error');
        createBtn.disabled = false;
        createBtn.textContent = originalText;
    }
}

function showEditRecordDialog(zoneId, rrsetId, recordName, recordType, currentRecords, currentTTL) {
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    // Parse current records (comma-separated)
    const recordsArray = currentRecords ? currentRecords.split(',').map(r => r.trim()) : [''];
    const firstRecord = recordsArray[0] || '';
    
    dialog.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="margin-top: 0;">Edit Record</h2>
            <p style="color: #666; margin-bottom: 20px;">Record: <strong>${escapeHtml(recordName === '@' ? '@' : recordName)}/${escapeHtml(recordType)}</strong></p>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Name:</label>
                <input type="text" id="editRecordName" placeholder="e.g. test or @ for root" value="${escapeHtml(recordName === '@' ? '' : recordName)}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666;">Leave empty or @ for root domain</small>
            </div>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Type:</label>
                <select id="editRecordType" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    <option value="A" ${recordType === 'A' ? 'selected' : ''}>A (IPv4)</option>
                    <option value="AAAA" ${recordType === 'AAAA' ? 'selected' : ''}>AAAA (IPv6)</option>
                </select>
            </div>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Value(s):</label>
                <input type="text" id="editRecordValue" placeholder="e.g. 192.168.1.1 or multiple values separated by comma" value="${escapeHtml(firstRecord)}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666;">Multiple values separated by comma (e.g. 1.2.3.4, 5.6.7.8)</small>
            </div>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">TTL (seconds):</label>
                <select id="editRecordTTL" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    <option value="60" ${currentTTL === 60 ? 'selected' : ''}>60s</option>
                    <option value="300" ${currentTTL === 300 ? 'selected' : ''}>300s</option>
                    <option value="600" ${currentTTL === 600 ? 'selected' : ''}>600s</option>
                    <option value="1800" ${currentTTL === 1800 ? 'selected' : ''}>1800s</option>
                    <option value="3600" ${currentTTL === 3600 || !currentTTL ? 'selected' : ''}>3600s</option>
                    <option value="86400" ${currentTTL === 86400 ? 'selected' : ''}>86400s</option>
                </select>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('.modal-overlay').remove()" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                <button id="confirmEditRecordBtn" data-zone-id="${escapeHtml(zoneId)}" data-rrset-id="${escapeHtml(rrsetId)}" class="btn btn-primary" style="padding: 10px 20px;">Save</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Close on overlay click
    dialog.addEventListener('click', function(e) {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
    
    // Add event listener to confirm button
    const confirmBtn = dialog.querySelector('#confirmEditRecordBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', function() {
            updateRecord(this.dataset.zoneId, this.dataset.rrsetId);
        });
    }
    
    // Focus on value input
    setTimeout(() => {
        document.getElementById('editRecordValue').focus();
    }, 100);
}

async function updateRecord(zoneId, rrsetId) {
    const nameInput = document.getElementById('editRecordName');
    const typeInput = document.getElementById('editRecordType');
    const valueInput = document.getElementById('editRecordValue');
    const ttlInput = document.getElementById('editRecordTTL');
    
    const name = nameInput.value.trim() || '@';
    const type = typeInput.value;
    const valueStr = valueInput.value.trim();
    const ttl = parseInt(ttlInput.value) || 3600;
    
    // Validation
    if (!name || name.trim() === '') {
        showToast('Please enter a name (or @ for root)', 'error');
        return;
    }
    
    // Validation
    if (!valueStr) {
        showToast('Please enter at least one value', 'error');
        return;
    }
    
    // Parse values (comma-separated)
    const records = valueStr.split(',').map(r => r.trim()).filter(r => r);
    
    if (records.length === 0) {
        showToast('Please enter at least one value', 'error');
        return;
    }
    
    // Basic IP validation for A/AAAA records
    if (type === 'A') {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        for (const record of records) {
            if (!ipv4Regex.test(record)) {
                showToast('Invalid IPv4 address: ' + record, 'error');
                return;
            }
        }
    } else if (type === 'AAAA') {
        const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        for (const record of records) {
            if (!ipv6Regex.test(record)) {
                showToast('Invalid IPv6 address: ' + record, 'error');
                return;
            }
        }
    }
    
    // Validate TTL against allowed values
    const allowedTTLValues = [60, 300, 600, 1800, 3600, 86400];
    if (!allowedTTLValues.includes(ttl)) {
        showToast('TTL must be one of the allowed values: 60, 300, 600, 1800, 3600, 86400 seconds', 'error');
        return;
    }
    
    // Disable button
    const updateBtn = document.getElementById('confirmEditRecordBtn');
    const originalText = updateBtn.textContent;
    updateBtn.disabled = true;
    updateBtn.textContent = 'Saving...';
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        const encodedZoneId = encodeURIComponent(zoneId);
        const encodedRrsetId = encodeURIComponent(rrsetId);
        let url = `/api/v1/zones/${encodedZoneId}/rrsets/${encodedRrsetId}`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                type: type,
                records: records,
                ttl: ttl
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            updateBtn.disabled = false;
            updateBtn.textContent = originalText;
            return;
        }
        
        const data = await response.json();
        showToast('Record successfully updated', 'success');
        
        // Close dialog
        const dialog = document.querySelector('.modal-overlay');
        if (dialog) {
            dialog.remove();
        }
        
        // Reload zones to show updated record
        await refreshZones();
        
    } catch (error) {
        showToast('Error updating: ' + error.message, 'error');
        updateBtn.disabled = false;
        updateBtn.textContent = originalText;
    }
}

function toggleZoneTable(zoneId) {
    const zoneIdEscaped = escapeHtml(zoneId);
    const contentDiv = document.getElementById(`zone-content-${zoneIdEscaped}`);
    const toggleIcon = document.getElementById(`toggle-icon-${zoneIdEscaped}`);
    
    if (!contentDiv) return;
    
    if (contentDiv.classList.contains('collapsed')) {
        contentDiv.classList.remove('collapsed');
        contentDiv.classList.add('expanded');
        if (toggleIcon) toggleIcon.textContent = '▼';
    } else {
        contentDiv.classList.remove('expanded');
        contentDiv.classList.add('collapsed');
        if (toggleIcon) toggleIcon.textContent = '▶';
    }
}

async function showCreateZoneDialog() {
    // Load tokens first
    let tokens = [];
    try {
        const tokensResponse = await fetch('/api/v1/config/api-tokens');
        if (tokensResponse.ok) {
            const tokensData = await tokensResponse.json();
            tokens = tokensData.tokens || [];
        }
    } catch (error) {
        console.error('Error loading tokens:', error);
    }
    
    if (tokens.length === 0) {
        showToast('No API tokens configured. Please add a token first.', 'error');
        return;
    }
    
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    // Build token select options
    let tokenOptions = '';
    tokens.forEach(token => {
        tokenOptions += `<option value="${token.id}">${token.name || 'Unnamed Token'}</option>`;
    });
    
    dialog.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="margin-top: 0;">Create New DNS Zone</h2>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">API Token:</label>
                <select id="newZoneTokenId" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                    ${tokenOptions}
                </select>
                <small style="color: #666;">Select the API token to use for this zone</small>
            </div>
            
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Zone Name (Domain):</label>
                <input type="text" id="newZoneName" placeholder="e.g. example.com" value="" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666;">Valid domain name (e.g. example.com)</small>
            </div>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Default TTL (seconds, optional):</label>
                <input type="number" id="newZoneTTL" value="" min="60" placeholder="3600" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666;">Leave empty for default TTL</small>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('.modal-overlay').remove()" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                <button onclick="createZone()" class="btn btn-primary" style="padding: 10px 20px;">Create</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Close on overlay click
    dialog.addEventListener('click', function(e) {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
    
    // Focus on name input
    setTimeout(() => {
        document.getElementById('newZoneName').focus();
    }, 100);
}

async function createZone() {
    const tokenSelect = document.getElementById('newZoneTokenId');
    const nameInput = document.getElementById('newZoneName');
    const ttlInput = document.getElementById('newZoneTTL');
    
    const tokenId = tokenSelect ? tokenSelect.value : null;
    const name = nameInput.value.trim();
    const ttl = ttlInput.value.trim() ? parseInt(ttlInput.value) : null;
    
    // Validation
    if (!tokenId) {
        showToast('Please select an API token', 'error');
        return;
    }
    
    if (!name) {
        showToast('Please enter a zone name', 'error');
        return;
    }
    
    // Basic domain validation
    const domainPattern = /^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
    if (!domainPattern.test(name)) {
        showToast('Invalid domain name. Please use a valid format (e.g. example.com)', 'error');
        return;
    }
    
    if (ttl && (ttl < 60 || ttl > 86400)) {
        showToast('TTL must be between 60 and 86400 seconds', 'error');
        return;
    }
    
    // Disable button
    const createBtn = event.target;
    const originalText = createBtn.textContent;
    createBtn.disabled = true;
    createBtn.textContent = 'Erstelle...';
    
    try {
        let url = '/api/v1/zones';
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name.toLowerCase(),
                ttl: ttl
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            createBtn.disabled = false;
            createBtn.textContent = originalText;
            return;
        }
        
        const data = await response.json();
        showToast('Zone successfully created', 'success');
        
        // Close dialog
        const dialog = document.querySelector('.modal-overlay');
        if (dialog) {
            dialog.remove();
        }
        
        // Reload zones to show new zone
        await loadZones();
        
    } catch (error) {
        showToast('Error creating: ' + error.message, 'error');
        createBtn.disabled = false;
        createBtn.textContent = originalText;
    }
}

function showDeleteZoneDialog(zoneId, zoneName, tokenId = null) {
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    dialog.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="margin-top: 0; color: #dc3545;">Delete Zone</h2>
            <p style="color: #666; margin-bottom: 20px;">Warning: This action cannot be undone!</p>
            <p style="margin-bottom: 15px;">To delete zone <strong>${escapeHtml(zoneName)}</strong>, enter the zone name to confirm:</p>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Zone Name:</label>
                <input type="text" id="deleteZoneConfirmation" placeholder="${escapeHtml(zoneName)}" value="" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('.modal-overlay').remove()" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                <button id="confirmDeleteZoneBtn" data-zone-id="${escapeHtml(zoneId)}" data-zone-name="${escapeHtml(zoneName)}" data-token-id="${tokenId || ''}" class="btn btn-danger" style="padding: 10px 20px;">Delete</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Close on overlay click
    dialog.addEventListener('click', function(e) {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
    
    // Focus on confirmation input
    setTimeout(() => {
        document.getElementById('deleteZoneConfirmation').focus();
    }, 100);
    
    // Add event listener to confirm button
    const confirmBtn = dialog.querySelector('#confirmDeleteZoneBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', function() {
            deleteZone(this.dataset.zoneId, this.dataset.zoneName, this.dataset.tokenId || null);
        });
    }
}

async function deleteZone(zoneId, zoneName, tokenId = null) {
    const confirmationInput = document.getElementById('deleteZoneConfirmation');
    const confirmation = confirmationInput.value.trim();
    
    if (confirmation !== zoneName) {
        showToast(`Confirmation failed. Please enter '${zoneName}'.`, 'error');
        return;
    }
    
    // Disable button
    const deleteBtn = event.target;
    const originalText = deleteBtn.textContent;
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';
    
    try {
        let url = `/api/v1/zones/${zoneId}`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                confirmation_name: confirmation
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            deleteBtn.disabled = false;
            deleteBtn.textContent = originalText;
            return;
        }
        
        const data = await response.json();
        showToast('Zone successfully deleted', 'success');
        
        // Close dialog
        const dialog = document.querySelector('.modal-overlay');
        if (dialog) {
            dialog.remove();
        }
        
        // Reload zones
        await loadZones();
        
    } catch (error) {
        showToast('Error deleting: ' + error.message, 'error');
        deleteBtn.disabled = false;
        deleteBtn.textContent = originalText;
    }
}

function showDeleteRecordDialog(zoneId, rrsetId, recordName, recordType) {
    const confirmationText = recordName === '@' ? `@/${recordType}` : `${recordName}/${recordType}`;
    const dialog = document.createElement('div');
    dialog.className = 'modal-overlay';
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';
    
    dialog.innerHTML = `
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 500px; width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h2 style="margin-top: 0; color: #dc3545;">Delete Record</h2>
            <p style="color: #666; margin-bottom: 20px;">Warning: This action cannot be undone!</p>
            <p style="margin-bottom: 15px;">To delete record <strong>${escapeHtml(confirmationText)}</strong>, enter the record name to confirm:</p>
            
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Record Name:</label>
                <input type="text" id="deleteRecordConfirmation" placeholder="${escapeHtml(confirmationText)}" value="" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('.modal-overlay').remove()" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                <button id="confirmDeleteRecordBtn" data-zone-id="${escapeHtml(zoneId)}" data-rrset-id="${escapeHtml(rrsetId)}" data-confirmation-text="${escapeHtml(confirmationText)}" class="btn btn-danger" style="padding: 10px 20px;">Delete</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Close on overlay click
    dialog.addEventListener('click', function(e) {
        if (e.target === dialog) {
            dialog.remove();
        }
    });
    
    // Focus on confirmation input
    setTimeout(() => {
        document.getElementById('deleteRecordConfirmation').focus();
    }, 100);
    
    // Add event listener to confirm button
    const confirmBtn = dialog.querySelector('#confirmDeleteRecordBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', function() {
            deleteRecord(this.dataset.zoneId, this.dataset.rrsetId, this.dataset.confirmationText);
        });
    }
}

async function deleteRecord(zoneId, rrsetId, confirmationText) {
    const confirmationInput = document.getElementById('deleteRecordConfirmation');
    const confirmation = confirmationInput.value.trim();
    
    if (confirmation !== confirmationText) {
        showToast(`Confirmation failed. Please enter '${confirmationText}'.`, 'error');
        return;
    }
    
    // Disable button
    const deleteBtn = event.target;
    const originalText = deleteBtn.textContent;
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';
    
    try {
        const tokenId = getTokenIdForZone(zoneId);
        let url = `/api/v1/zones/${zoneId}/rrsets/${encodeURIComponent(rrsetId)}`;
        if (tokenId) {
            url += `?token_id=${encodeURIComponent(tokenId)}`;
        }
        const response = await fetch(url, {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                confirmation_name: confirmation
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            deleteBtn.disabled = false;
            deleteBtn.textContent = originalText;
            return;
        }
        
        const data = await response.json();
        showToast('Record successfully deleted', 'success');
        
        // Close dialog
        const dialog = document.querySelector('.modal-overlay');
        if (dialog) {
            dialog.remove();
        }
        
        // Reload zones to show updated records
        await refreshZones();
        
    } catch (error) {
        showToast('Error deleting: ' + error.message, 'error');
        deleteBtn.disabled = false;
        deleteBtn.textContent = originalText;
    }
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = message;
        toast.className = 'toast show ' + type;
        
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }
}

// Security Configuration Functions
async function loadSecurityConfig() {
    try {
        const response = await fetch('/api/v1/security/config');
        if (!response.ok) {
            throw new Error('Failed to load security config');
        }
        const data = await response.json();
        
        // Update 2FA status
        const statusText = document.getElementById('2faStatusText');
        if (statusText) {
            statusText.textContent = data.two_factor_enabled ? 'Enabled' : 'Disabled';
        }
        
        // Show/hide 2FA sections
        const setupSection = document.getElementById('2faSetupSection');
        const verifySection = document.getElementById('2faVerifySection');
        const disableSection = document.getElementById('2faDisableSection');
        const backupCodesSection = document.getElementById('2faBackupCodesSection');
        
        if (data.two_factor_enabled) {
            if (setupSection) setupSection.style.display = 'none';
            if (verifySection) verifySection.style.display = 'none';
            if (disableSection) disableSection.style.display = 'block';
            if (backupCodesSection) backupCodesSection.style.display = 'block';
        } else {
            if (setupSection) setupSection.style.display = 'block';
            if (verifySection) verifySection.style.display = 'none';
            if (disableSection) disableSection.style.display = 'none';
            if (backupCodesSection) backupCodesSection.style.display = 'none';
        }
        
        // Load IP access control
        await loadIPAccessControl();
        
        // Load brute-force protection config
        await loadBruteForceConfig();
        
        // Load SMTP config
        await loadSMTPConfig();
        
        // Load backup codes status if 2FA is enabled
        if (data.two_factor_enabled) {
            await loadBackupCodesStatus();
        }
    } catch (error) {
        console.error('Error loading security config:', error);
        showToast('Error loading security configuration', 'error');
    }
}

async function changePassword() {
    const currentPassword = document.getElementById('currentPasswordInput').value;
    const newPassword = document.getElementById('newPasswordInput').value;
    
    if (!currentPassword || !newPassword) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    // Validate password strength
    if (newPassword.length < 12) {
        showToast('Password must be at least 12 characters long', 'error');
        return;
    }
    
    if (!/\d/.test(newPassword)) {
        showToast('Password must contain at least one number', 'error');
        return;
    }
    
    if (!/[A-Z]/.test(newPassword)) {
        showToast('Password must contain at least one uppercase letter', 'error');
        return;
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(newPassword)) {
        showToast('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;\':",./<>?)', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/password/change', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        let data;
        try {
            data = await response.json();
        } catch (e) {
            data = { detail: response.statusText || 'Unknown error' };
        }
        
        if (response.ok) {
            showToast('Password changed successfully', 'success');
            document.getElementById('currentPasswordInput').value = '';
            document.getElementById('newPasswordInput').value = '';
        } else {
            showToast(data.detail || data.message || 'Error changing password', 'error');
            console.error('Password change error:', data);
        }
    } catch (error) {
        showToast('Error changing password: ' + error.message, 'error');
        console.error('Password change exception:', error);
    }
}

async function setup2FA() {
    const password = document.getElementById('2faPasswordInput').value;
    
    if (!password) {
        showToast('Please enter your password', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/2fa/setup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ password: password })
        });
        
        let data;
        try {
            data = await response.json();
        } catch (e) {
            data = { detail: response.statusText || 'Unknown error' };
        }
        
        if (response.ok) {
            // Show QR code (no backup codes shown automatically)
            document.getElementById('2faQRCode').src = data.qr_code;
            
            // Show verify section
            document.getElementById('2faSetupSection').style.display = 'none';
            document.getElementById('2faVerifySection').style.display = 'block';
            document.getElementById('2faPasswordInput').value = '';
        } else {
            showToast(data.detail || data.message || 'Error setting up 2FA', 'error');
            console.error('2FA setup error:', data);
        }
    } catch (error) {
        showToast('Error setting up 2FA: ' + error.message, 'error');
        console.error('2FA setup exception:', error);
    }
}

async function verify2FA() {
    const token = document.getElementById('2faTokenInput').value;
    
    if (!token) {
        showToast('Please enter the 2FA token', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/2fa/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: token })
        });
        
        let data;
        try {
            data = await response.json();
        } catch (e) {
            data = { detail: response.statusText || 'Unknown error' };
        }
        
        if (response.ok) {
            showToast('2FA enabled successfully', 'success');
            document.getElementById('2faTokenInput').value = '';
            loadSecurityConfig(); // Reload to update UI
        } else {
            showToast(data.detail || data.message || 'Invalid 2FA token', 'error');
            console.error('2FA verify error:', data);
        }
    } catch (error) {
        showToast('Error verifying 2FA: ' + error.message, 'error');
        console.error('2FA verify exception:', error);
    }
}

async function disable2FA() {
    const password = document.getElementById('2faDisablePasswordInput').value;
    
    if (!password) {
        showToast('Please enter your password', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/2fa/disable', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ password: password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('2FA disabled successfully', 'success');
            document.getElementById('2faDisablePasswordInput').value = '';
            loadSecurityConfig(); // Reload to update UI
        } else {
            showToast(data.detail || 'Error disabling 2FA', 'error');
        }
    } catch (error) {
        showToast('Error disabling 2FA: ' + error.message, 'error');
    }
}

async function generateBackupCodes() {
    if (!confirm('This will generate new backup codes. Any existing backup codes will be replaced. Continue?')) {
        return;
    }
    
    const btn = document.getElementById('generateBackupCodesBtn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Generating...';
    
    try {
        const response = await fetch('/api/v1/security/2fa/backup-codes/generate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        let data;
        try {
            data = await response.json();
        } catch (e) {
            data = { detail: response.statusText || 'Unknown error' };
        }
        
        if (response.ok) {
            // Show backup codes in a popup modal
            showBackupCodesModal(data.backup_codes);
            
            // Reload status
            await loadBackupCodesStatus();
            
            showToast('Backup codes generated successfully. Please save them securely!', 'success');
        } else {
            showToast(data.detail || data.message || 'Error generating backup codes', 'error');
            console.error('Backup codes generation error:', data);
        }
    } catch (error) {
        showToast('Error generating backup codes: ' + error.message, 'error');
        console.error('Backup codes generation exception:', error);
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

function showBackupCodesModal(backupCodes) {
    // Remove existing modal if any
    const existingModal = document.getElementById('backupCodesModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create modal overlay
    const modal = document.createElement('div');
    modal.id = 'backupCodesModal';
    modal.className = 'modal-overlay';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 2000; display: flex; align-items: center; justify-content: center;';
    
    // Create modal content
    const modalContent = document.createElement('div');
    modalContent.style.cssText = 'background: white; padding: 30px; border-radius: 8px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 20px rgba(0,0,0,0.3);';
    
    modalContent.innerHTML = `
        <h2 style="margin-top: 0; color: #333;">Backup Codes</h2>
        <p style="color: #d32f2f; font-weight: bold; margin-bottom: 15px;">⚠️ These codes will only be shown once. Save them securely!</p>
        <div id="backupCodesList" style="font-family: 'Courier New', monospace; background: #f5f5f5; padding: 15px; border-radius: 4px; border: 1px solid #ddd; margin-bottom: 15px;">
            ${backupCodes.map((code, index) => `<div style="margin-bottom: 8px; padding: 8px; background: white; border: 1px solid #ddd; border-radius: 3px; font-size: 0.9em; word-break: break-all;">${index + 1}. ${code}</div>`).join('')}
        </div>
        <button id="closeBackupCodesModal" class="btn btn-primary" style="width: 100%;">Close</button>
    `;
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // Close button handler
    document.getElementById('closeBackupCodesModal').addEventListener('click', function() {
        modal.remove();
    });
    
    // Close on overlay click
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.remove();
        }
    });
    
    // Close on Escape key
    const escapeHandler = function(e) {
        if (e.key === 'Escape') {
            modal.remove();
            document.removeEventListener('keydown', escapeHandler);
        }
    };
    document.addEventListener('keydown', escapeHandler);
}

async function loadBackupCodesStatus() {
    try {
        const response = await fetch('/api/v1/security/2fa/backup-codes/status');
        if (!response.ok) {
            throw new Error('Failed to load backup codes status');
        }
        const data = await response.json();
        
        const statusText = document.getElementById('backupCodesStatusText');
        if (statusText) {
            if (data.enabled) {
                statusText.textContent = `Enabled (${data.count} codes available)`;
                statusText.style.color = '#28a745';
            } else {
                statusText.textContent = 'Disabled';
                statusText.style.color = '#dc3545';
            }
        }
    } catch (error) {
        console.error('Error loading backup codes status:', error);
        const statusText = document.getElementById('backupCodesStatusText');
        if (statusText) {
            statusText.textContent = 'Error loading status';
            statusText.style.color = '#dc3545';
        }
    }
}

async function loadIPAccessControl() {
    try {
        const response = await fetch('/api/v1/security/ip-access-control');
        if (!response.ok) {
            throw new Error('Failed to load IP access control');
        }
        const data = await response.json();
        
        // Update checkboxes
        document.getElementById('whitelistEnabled').checked = data.whitelist_enabled;
        document.getElementById('blacklistEnabled').checked = data.blacklist_enabled;
        
        // Display whitelist IPs
        const whitelistDiv = document.getElementById('whitelistIpsList');
        if (whitelistDiv) {
            if (data.whitelist_ips.length === 0) {
                whitelistDiv.innerHTML = '<p>No IPs in whitelist</p>';
            } else {
                whitelistDiv.innerHTML = data.whitelist_ips.map(ip => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; background: #f5f5f5; margin-bottom: 5px; border-radius: 4px;">
                        <span>${ip}</span>
                        <button class="btn btn-secondary" onclick="removeWhitelistIp('${ip}')" style="padding: 4px 8px; font-size: 0.9em;">Remove</button>
                    </div>
                `).join('');
            }
        }
        
        // Display blacklist IPs
        const blacklistDiv = document.getElementById('blacklistIpsList');
        if (blacklistDiv) {
            if (data.blacklist_ips.length === 0) {
                blacklistDiv.innerHTML = '<p>No IPs in blacklist</p>';
            } else {
                blacklistDiv.innerHTML = data.blacklist_ips.map(ip => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; background: #f5f5f5; margin-bottom: 5px; border-radius: 4px;">
                        <span>${ip}</span>
                        <button class="btn btn-secondary" onclick="removeBlacklistIp('${ip}')" style="padding: 4px 8px; font-size: 0.9em;">Remove</button>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading IP access control:', error);
        showToast('Error loading IP access control', 'error');
    }
}

async function toggleWhitelist() {
    const enabled = document.getElementById('whitelistEnabled').checked;
    
    try {
        const response = await fetch('/api/v1/security/ip-access-control/whitelist/enabled', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(enabled)
        });
        
        if (response.ok) {
            showToast(`Whitelist ${enabled ? 'enabled' : 'disabled'}`, 'success');
        } else {
            showToast('Error toggling whitelist', 'error');
        }
    } catch (error) {
        showToast('Error toggling whitelist: ' + error.message, 'error');
    }
}

async function toggleBlacklist() {
    const enabled = document.getElementById('blacklistEnabled').checked;
    
    try {
        const response = await fetch('/api/v1/security/ip-access-control/blacklist/enabled', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(enabled)
        });
        
        if (response.ok) {
            showToast(`Blacklist ${enabled ? 'enabled' : 'disabled'}`, 'success');
        } else {
            showToast('Error toggling blacklist', 'error');
        }
    } catch (error) {
        showToast('Error toggling blacklist: ' + error.message, 'error');
    }
}

async function addWhitelistIp() {
    const ipInput = document.getElementById('whitelistIpInput');
    const ip = ipInput.value.trim();
    
    if (!ip) {
        showToast('Please enter an IP or CIDR', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/ip-access-control/whitelist/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip_or_cidr: ip })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('IP added to whitelist', 'success');
            ipInput.value = '';
            loadIPAccessControl();
        } else {
            showToast(data.detail || 'Error adding IP to whitelist', 'error');
        }
    } catch (error) {
        showToast('Error adding IP to whitelist: ' + error.message, 'error');
    }
}

async function removeWhitelistIp(ip) {
    try {
        const response = await fetch(`/api/v1/security/ip-access-control/whitelist/${encodeURIComponent(ip)}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('IP removed from whitelist', 'success');
            loadIPAccessControl();
        } else {
            showToast('Error removing IP from whitelist', 'error');
        }
    } catch (error) {
        showToast('Error removing IP from whitelist: ' + error.message, 'error');
    }
}

async function addBlacklistIp() {
    const ipInput = document.getElementById('blacklistIpInput');
    const ip = ipInput.value.trim();
    
    if (!ip) {
        showToast('Please enter an IP or CIDR', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/ip-access-control/blacklist/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip_or_cidr: ip })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('IP added to blacklist', 'success');
            ipInput.value = '';
            loadIPAccessControl();
        } else {
            showToast(data.detail || 'Error adding IP to blacklist', 'error');
        }
    } catch (error) {
        showToast('Error adding IP to blacklist: ' + error.message, 'error');
    }
}

async function removeBlacklistIp(ip) {
    try {
        const response = await fetch(`/api/v1/security/ip-access-control/blacklist/${encodeURIComponent(ip)}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showToast('IP removed from blacklist', 'success');
            loadIPAccessControl();
        } else {
            showToast('Error removing IP from blacklist', 'error');
        }
    } catch (error) {
        showToast('Error removing IP from blacklist: ' + error.message, 'error');
    }
}

// Add event listeners for security tab
document.addEventListener('DOMContentLoaded', function() {
    const changePasswordBtn = document.getElementById('changePasswordBtn');
    if (changePasswordBtn) {
        changePasswordBtn.addEventListener('click', changePassword);
    }
    
    const setup2faBtn = document.getElementById('setup2faBtn');
    if (setup2faBtn) {
        setup2faBtn.addEventListener('click', setup2FA);
    }
    
    const verify2faBtn = document.getElementById('verify2faBtn');
    if (verify2faBtn) {
        verify2faBtn.addEventListener('click', verify2FA);
    }
    
    const disable2faBtn = document.getElementById('disable2faBtn');
    if (disable2faBtn) {
        disable2faBtn.addEventListener('click', disable2FA);
    }
    
    const generateBackupCodesBtn = document.getElementById('generateBackupCodesBtn');
    if (generateBackupCodesBtn) {
        generateBackupCodesBtn.addEventListener('click', generateBackupCodes);
    }
});

// Brute-Force Protection Functions
async function loadBruteForceConfig() {
    try {
        const response = await fetch('/api/v1/security/brute-force');
        if (!response.ok) {
            throw new Error('Failed to load brute-force config');
        }
        const data = await response.json();
        
        const enabledCheckbox = document.getElementById('bruteForceEnabled');
        const settingsDiv = document.getElementById('bruteForceSettings');
        
        if (enabledCheckbox) {
            enabledCheckbox.checked = data.enabled;
        }
        
        if (settingsDiv) {
            settingsDiv.style.display = data.enabled ? 'block' : 'none';
        }
        
        // Convert seconds to minutes for display
        document.getElementById('maxLoginAttempts').value = data.max_login_attempts;
        document.getElementById('max2FAAttempts').value = data.max_2fa_attempts;
        document.getElementById('loginLockoutDuration').value = Math.floor(data.lockout_duration_login / 60);
        document.getElementById('2faLockoutDuration').value = Math.floor(data.lockout_duration_2fa / 60);
        document.getElementById('timeWindow').value = Math.floor(data.window_duration / 60);
    } catch (error) {
        console.error('Error loading brute-force config:', error);
    }
}

function toggleBruteForce() {
    const enabledCheckbox = document.getElementById('bruteForceEnabled');
    const settingsDiv = document.getElementById('bruteForceSettings');
    
    if (enabledCheckbox && settingsDiv) {
        settingsDiv.style.display = enabledCheckbox.checked ? 'block' : 'none';
    }
}

async function saveBruteForceSettings() {
    const enabledCheckbox = document.getElementById('bruteForceEnabled');
    const maxLoginAttempts = document.getElementById('maxLoginAttempts');
    const max2FAAttempts = document.getElementById('max2FAAttempts');
    const loginLockoutDuration = document.getElementById('loginLockoutDuration');
    const twoFALockoutDuration = document.getElementById('2faLockoutDuration');
    const timeWindow = document.getElementById('timeWindow');
    
    if (!enabledCheckbox || !maxLoginAttempts || !max2FAAttempts || !loginLockoutDuration || !twoFALockoutDuration || !timeWindow) {
        showToast('Error: Form elements not found', 'error');
        return;
    }
    
    const config = {
        enabled: enabledCheckbox.checked,
        max_login_attempts: parseInt(maxLoginAttempts.value),
        max_2fa_attempts: parseInt(max2FAAttempts.value),
        lockout_duration_login: parseInt(loginLockoutDuration.value),
        lockout_duration_2fa: parseInt(twoFALockoutDuration.value),
        window_duration: parseInt(timeWindow.value)
    };
    
    // Validation
    if (config.max_login_attempts < 1 || config.max_login_attempts > 20) {
        showToast('Max login attempts must be between 1 and 20', 'error');
        return;
    }
    if (config.max_2fa_attempts < 1 || config.max_2fa_attempts > 10) {
        showToast('Max 2FA attempts must be between 1 and 10', 'error');
        return;
    }
    if (config.lockout_duration_login < 1 || config.lockout_duration_login > 1440) {
        showToast('Login lockout duration must be between 1 and 1440 minutes', 'error');
        return;
    }
    if (config.lockout_duration_2fa < 1 || config.lockout_duration_2fa > 1440) {
        showToast('2FA lockout duration must be between 1 and 1440 minutes', 'error');
        return;
    }
    if (config.window_duration < 1 || config.window_duration > 1440) {
        showToast('Time window must be between 1 and 1440 minutes', 'error');
        return;
    }
    
    const saveBtn = document.getElementById('saveBruteForceBtn');
    const originalText = saveBtn ? saveBtn.textContent : 'Save';
    
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
    }
    
    try {
        const response = await fetch('/api/v1/security/brute-force', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.textContent = originalText;
            }
            return;
        }
        
        showToast('Brute-force protection settings saved', 'success');
        
        // Reload config to ensure UI is in sync
        await loadBruteForceConfig();
        
    } catch (error) {
        showToast('Error saving settings: ' + error.message, 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = originalText;
        }
    }
}

// Audit Logs Functions
async function loadAuditLogs() {
    const displayDiv = document.getElementById('auditLogsDisplay');
    if (!displayDiv) return;
    
    displayDiv.innerHTML = '<p style="color: #666;">Loading logs...</p>';
    
    try {
        // Get filter values
        const actionFilter = document.getElementById('auditLogActionFilter')?.value || '';
        const usernameFilter = document.getElementById('auditLogUsernameFilter')?.value || '';
        const startDateFilter = document.getElementById('auditLogStartDateFilter')?.value || '';
        const endDateFilter = document.getElementById('auditLogEndDateFilter')?.value || '';
        const limitFilter = parseInt(document.getElementById('auditLogLimitFilter')?.value || '100');
        
        // Build query parameters
        const params = new URLSearchParams();
        params.append('limit', limitFilter.toString());
        if (actionFilter) params.append('action', actionFilter);
        if (usernameFilter) params.append('username', usernameFilter);
        if (startDateFilter) {
            // Convert local datetime to ISO format
            const startDate = new Date(startDateFilter);
            params.append('start_date', startDate.toISOString());
        }
        if (endDateFilter) {
            // Convert local datetime to ISO format
            const endDate = new Date(endDateFilter);
            params.append('end_date', endDate.toISOString());
        }
        
        const response = await fetch(`/api/v1/security/audit-logs?${params.toString()}`);
        if (!response.ok) {
            throw new Error('Failed to load audit logs');
        }
        
        const data = await response.json();
        
        if (!data.logs || data.logs.length === 0) {
            displayDiv.innerHTML = '<p style="color: #666;">No logs found matching the filters.</p>';
            return;
        }
        
        // Build table HTML
        let tableHTML = `
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; background: white;">
                    <thead>
                        <tr style="background: #f5f5f5;">
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">Timestamp</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">Action</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">Username</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">IP Address</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">Status</th>
                            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold;">Details</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        data.logs.forEach(log => {
            const timestamp = new Date(log.timestamp).toLocaleString('de-DE');
            const statusClass = log.success ? 'success' : 'error';
            const statusText = log.success ? '✓ Success' : '✗ Failed';
            const statusColor = log.success ? '#28a745' : '#dc3545';
            
            // Format action name
            const actionName = log.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            // Format details
            let detailsText = '';
            if (log.details) {
                const details = Object.entries(log.details).map(([key, value]) => `${key}: ${value}`).join(', ');
                detailsText = details;
            }
            if (log.error) {
                detailsText += (detailsText ? ' | ' : '') + `Error: ${log.error}`;
            }
            
            tableHTML += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 10px; color: #666; font-family: monospace; font-size: 0.9em;">${timestamp}</td>
                    <td style="padding: 10px;">
                        <span style="display: inline-block; padding: 4px 8px; background: #e3f2fd; color: #1976d2; border-radius: 4px; font-size: 0.85em; font-weight: bold;">${actionName}</span>
                    </td>
                    <td style="padding: 10px; color: #333; font-weight: 500;">${log.username || 'unknown'}</td>
                    <td style="padding: 10px; color: #666; font-family: monospace; font-size: 0.9em;">${log.ip || 'unknown'}</td>
                    <td style="padding: 10px;">
                        <span style="color: ${statusColor}; font-weight: bold;">${statusText}</span>
                    </td>
                    <td style="padding: 10px; color: #666; font-size: 0.9em; max-width: 300px; word-wrap: break-word;">${detailsText || '-'}</td>
                </tr>
            `;
        });
        
        tableHTML += `
                    </tbody>
                </table>
            </div>
            <p style="margin-top: 15px; color: #666; font-size: 0.9em;">Showing ${data.count} log entries</p>
        `;
        
        displayDiv.innerHTML = tableHTML;
        
    } catch (error) {
        console.error('Error loading audit logs:', error);
        displayDiv.innerHTML = `<p style="color: #dc3545;">Error loading audit logs: ${error.message}</p>`;
    }
}

function clearAuditLogFilters() {
    document.getElementById('auditLogActionFilter').value = '';
    document.getElementById('auditLogUsernameFilter').value = '';
    document.getElementById('auditLogStartDateFilter').value = '';
    document.getElementById('auditLogEndDateFilter').value = '';
    document.getElementById('auditLogLimitFilter').value = '100';
    loadAuditLogs();
}

// Audit Log Settings Functions
async function loadAuditLogSettings() {
    try {
        const response = await fetch('/api/v1/security/audit-log-config');
        if (!response.ok) {
            throw new Error('Failed to load audit log settings');
        }
        
        const data = await response.json();
        
        // Fill form fields
        document.getElementById('auditLogMaxSizeMB').value = data.max_size_mb || 10;
        document.getElementById('auditLogMaxAgeDays').value = data.max_age_days || 30;
        document.getElementById('auditLogRotationIntervalHours').value = data.rotation_interval_hours || 24;
    } catch (error) {
        console.error('Error loading audit log settings:', error);
        showToast('Error loading audit log settings', 'error');
    }
}

async function saveAuditLogSettings() {
    const saveBtn = document.getElementById('saveAuditLogSettingsBtn');
    const originalText = saveBtn.textContent;
    
    try {
        saveBtn.textContent = 'Saving...';
        saveBtn.disabled = true;
        
        const maxSizeMB = parseInt(document.getElementById('auditLogMaxSizeMB').value);
        const maxAgeDays = parseInt(document.getElementById('auditLogMaxAgeDays').value);
        const rotationIntervalHours = parseInt(document.getElementById('auditLogRotationIntervalHours').value);
        
        // Validate
        if (isNaN(maxSizeMB) || maxSizeMB < 1 || maxSizeMB > 1000) {
            throw new Error('Max file size must be between 1 and 1000 MB');
        }
        if (isNaN(maxAgeDays) || maxAgeDays < 1 || maxAgeDays > 365) {
            throw new Error('Max age must be between 1 and 365 days');
        }
        if (isNaN(rotationIntervalHours) || rotationIntervalHours < 1 || rotationIntervalHours > 168) {
            throw new Error('Rotation interval must be between 1 and 168 hours');
        }
        
        const response = await fetch('/api/v1/security/audit-log-config', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                max_size_mb: maxSizeMB,
                max_age_days: maxAgeDays,
                rotation_interval_hours: rotationIntervalHours
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to save audit log settings');
        }
        
        showToast('Audit log settings saved successfully', 'success');
    } catch (error) {
        console.error('Error saving audit log settings:', error);
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        saveBtn.textContent = originalText;
        saveBtn.disabled = false;
    }
}

async function loadSMTPConfig() {
    try {
        const response = await fetch('/api/v1/security/smtp');
        if (!response.ok) {
            throw new Error('Failed to load SMTP config');
        }
        const data = await response.json();
        
        // Update form fields
        document.getElementById('smtpEnabled').checked = data.enabled;
        document.getElementById('smtpHost').value = data.host || '';
        document.getElementById('smtpPort').value = data.port || 587;
        document.getElementById('smtpUser').value = data.user || '';
        document.getElementById('smtpPassword').value = ''; // Don't show password
        document.getElementById('smtpUseTLS').checked = data.use_tls !== false;
        document.getElementById('smtpFrom').value = data.from_address || '';
        document.getElementById('smtpTo').value = data.to_address || '';
        
        // Update enabled events checkboxes
        const checkboxes = document.querySelectorAll('.smtp-event-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = data.enabled_events && data.enabled_events.includes(checkbox.value);
        });
        
        // Show/hide settings
        toggleSMTP();
    } catch (error) {
        console.error('Error loading SMTP config:', error);
        showToast('Error loading SMTP configuration', 'error');
    }
}

function toggleSMTP() {
    const enabledCheckbox = document.getElementById('smtpEnabled');
    const settingsDiv = document.getElementById('smtpSettings');
    
    if (enabledCheckbox && settingsDiv) {
        settingsDiv.style.display = enabledCheckbox.checked ? 'block' : 'none';
    }
}

async function saveSMTPConfig() {
    const enabledCheckbox = document.getElementById('smtpEnabled');
    const host = document.getElementById('smtpHost').value.trim();
    const port = parseInt(document.getElementById('smtpPort').value);
    const user = document.getElementById('smtpUser').value.trim();
    const password = document.getElementById('smtpPassword').value;
    const useTLS = document.getElementById('smtpUseTLS').checked;
    const fromAddress = document.getElementById('smtpFrom').value.trim();
    const toAddress = document.getElementById('smtpTo').value.trim();
    
    // Get selected events
    const enabledEvents = [];
    const checkboxes = document.querySelectorAll('.smtp-event-checkbox');
    checkboxes.forEach(checkbox => {
        if (checkbox.checked) {
            enabledEvents.push(checkbox.value);
        }
    });
    
    // Validation
    if (enabledCheckbox.checked) {
        if (!host) {
            showToast('SMTP Host ist erforderlich', 'error');
            return;
        }
        if (!port || port < 1 || port > 65535) {
            showToast('Ungültiger Port', 'error');
            return;
        }
        if (!fromAddress) {
            showToast('From-Adresse ist erforderlich', 'error');
            return;
        }
        if (!toAddress) {
            showToast('To-Adresse ist erforderlich', 'error');
            return;
        }
    }
    
    const saveBtn = document.getElementById('saveSMTPBtn');
    const originalText = saveBtn ? saveBtn.textContent : '';
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
    }
    
    try {
        const config = {
            enabled: enabledCheckbox.checked,
            host: host,
            port: port,
            user: user,
            password: password || '***', // Use '***' to keep existing password if empty
            use_tls: useTLS,
            from_address: fromAddress,
            to_address: toAddress,
            enabled_events: enabledEvents
        };
        
        const response = await fetch('/api/v1/security/smtp', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({detail: 'Unknown error'}));
            showToast('Error: ' + (errorData.detail || response.statusText), 'error');
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.textContent = originalText;
            }
            return;
        }
        
        showToast('SMTP configuration saved', 'success');
        
        // Clear password field
        document.getElementById('smtpPassword').value = '';
        
        // Reload config to ensure UI is in sync
        await loadSMTPConfig();
        
    } catch (error) {
        showToast('Error saving: ' + error.message, 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = originalText;
        }
    }
}

// ==================== Peer-Sync Functions ====================

// Load Peer-Sync configuration
async function loadPeerSyncConfig() {
    try {
        const response = await fetch('/api/v1/peer-sync/config');
        if (!response.ok) throw new Error('Failed to load peer-sync config');
        const config = await response.json();
        
        // Update UI
        document.getElementById('peerSyncEnabled').checked = config.enabled;
        document.getElementById('peerSyncInterval').value = config.interval;
        document.getElementById('peerSyncTimeout').value = config.timeout;
        document.getElementById('peerSyncMaxRetries').value = config.max_retries;
        document.getElementById('peerSyncRateLimit').value = config.rate_limit;
        document.getElementById('peerSyncNtpEnabled').checked = config.ntp_enabled;
        
        // Load peer nodes with keys (combined)
        const peerNodesList = document.getElementById('peerNodesList');
        peerNodesList.innerHTML = '';
        
        // Create a map of peer nodes to their public keys
        const peerMap = new Map();
        config.peer_nodes.forEach(peer => {
            const peerIp = peer.split(':')[0];
            peerMap.set(peer, {
                ip: peerIp,
                address: peer,
                public_key: config.peer_public_keys?.[peerIp]?.public_key || '',
                name: config.peer_public_keys?.[peerIp]?.name || peerIp
            });
        });
        
        // Also add peers that have public keys but are not in peer_nodes
        Object.entries(config.peer_public_keys || {}).forEach(([peerIp, peerData]) => {
            const peerAddress = `${peerIp}:8412`; // Default port
            if (!peerMap.has(peerAddress)) {
                // Find matching peer node with same IP
                const matchingPeer = config.peer_nodes.find(p => p.startsWith(peerIp + ':'));
                if (matchingPeer) {
                    peerMap.set(matchingPeer, {
                        ip: peerIp,
                        address: matchingPeer,
                        public_key: peerData.public_key || '',
                        name: peerData.name || peerIp
                    });
                } else {
                    peerMap.set(peerAddress, {
                        ip: peerIp,
                        address: peerAddress,
                        public_key: peerData.public_key || '',
                        name: peerData.name || peerIp
                    });
                }
            }
        });
        
        // Display all peers
        peerMap.forEach((peerData, peerAddress) => {
            const div = document.createElement('div');
            div.style.cssText = 'border: 1px solid #ddd; padding: 15px; border-radius: 4px; margin-bottom: 10px;';
            div.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4 style="margin: 0;">${peerData.name}</h4>
                    <button class="btn btn-secondary" onclick="removePeerNode('${peerAddress}')">Remove</button>
                </div>
                <div style="margin-bottom: 10px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Peer Address (IP:Port):</label>
                    <input type="text" value="${peerAddress}" readonly style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                </div>
                <div style="margin-bottom: 10px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Peer Name:</label>
                    <input type="text" id="peerName_${peerData.ip}" value="${peerData.name}" onchange="updatePeerName('${peerData.ip}', this.value)" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                </div>
                <div>
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Public Key:</label>
                    <input type="text" id="peerPublicKey_${peerData.ip}" value="${peerData.public_key}" onchange="updatePeerPublicKey('${peerData.ip}', this.value)" placeholder="Enter public key (32 bytes Base64)" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; font-size: 0.85em;">
                </div>
            `;
            peerNodesList.appendChild(div);
        });
        
        // Load public keys
        await loadPeerSyncPublicKeys();
        
    } catch (error) {
        console.error('Error loading peer-sync config:', error);
        showToast('Error loading peer-sync config: ' + error.message, 'error');
    }
}

// Load own public key
async function loadPeerSyncPublicKeys() {
    try {
        const response = await fetch('/api/v1/peer-sync/public-keys');
        if (!response.ok) throw new Error('Failed to load public key');
        const keys = await response.json();
        
        document.getElementById('peerPublicKey').value = keys.public_key || '';
    } catch (error) {
        console.error('Error loading public key:', error);
    }
}

// Regenerate X25519 key pair
async function regeneratePeerKey() {
    if (!confirm('Do you really want to generate a new private key? The old public key will become invalid and must be updated on all other peers!')) {
        return;
    }
    
    try {
        const response = await fetch('/api/v1/peer-sync/regenerate-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (!response.ok) throw new Error('Failed to regenerate key');
        
        const result = await response.json();
        showToast('Key pair successfully regenerated. Please update the new public key on all other peers!', 'success');
        
        // Reload public key
        await loadPeerSyncPublicKeys();
    } catch (error) {
        showToast('Error regenerating key: ' + error.message, 'error');
    }
}

// Toggle Peer-Sync
async function togglePeerSync() {
    await savePeerSyncConfig();
}

// Save Peer-Sync configuration
async function savePeerSyncConfig() {
    try {
        // Get current config to preserve peer_nodes and peer_public_keys
        const currentResponse = await fetch('/api/v1/peer-sync/config');
        const currentConfig = await currentResponse.json();
        
        const config = {
            enabled: document.getElementById('peerSyncEnabled').checked,
            peer_nodes: currentConfig.peer_nodes || [],
            interval: parseInt(document.getElementById('peerSyncInterval').value),
            timeout: parseInt(document.getElementById('peerSyncTimeout').value),
            max_retries: parseInt(document.getElementById('peerSyncMaxRetries').value),
            rate_limit: parseFloat(document.getElementById('peerSyncRateLimit').value),
            ntp_enabled: document.getElementById('peerSyncNtpEnabled').checked,
            peer_public_keys: currentConfig.peer_public_keys || {}
        };
        
        const response = await fetch('/api/v1/peer-sync/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        
        if (!response.ok) throw new Error('Failed to save peer-sync config');
        
        showToast('Peer-Sync configuration saved', 'success');
        await loadPeerSyncConfig();
        await loadPeerSyncStatus();
    } catch (error) {
        showToast('Error saving peer-sync config: ' + error.message, 'error');
    }
}

// Add peer node
async function addPeerNode() {
    const input = document.getElementById('newPeerNodeInput');
    const peerAddress = input.value.trim();
    
    if (!peerAddress) {
        showToast('Please enter a peer node (IP:Port)', 'error');
        return;
    }
    
    const peerName = prompt('Enter Peer Name (optional):') || peerAddress.split(':')[0];
    const peerPublicKey = prompt('Enter Peer Public Key (32 bytes Base64, optional - can be added later):') || '';
    
    // Basic validation (32 bytes = 44 Base64 chars)
    if (peerPublicKey && peerPublicKey.length !== 44) {
        showToast('Invalid public key format. Should be 32 bytes Base64 (44 characters). Peer node added without key.', 'warning');
    }
    
    try {
        const currentResponse = await fetch('/api/v1/peer-sync/config');
        const currentConfig = await currentResponse.json();
        
        if (currentConfig.peer_nodes.includes(peerAddress)) {
            showToast('Peer node already exists', 'error');
            return;
        }
        
        const peerIp = peerAddress.split(':')[0];
        const peerNodes = [...currentConfig.peer_nodes, peerAddress];
        const peerPublicKeys = { ...currentConfig.peer_public_keys };
        
        // Add/update peer public key
        if (peerPublicKey) {
            peerPublicKeys[peerIp] = {
                name: peerName,
                public_key: peerPublicKey
            };
        } else if (!peerPublicKeys[peerIp]) {
            // Create entry without public key if it doesn't exist
            peerPublicKeys[peerIp] = {
                name: peerName,
                public_key: ''
            };
        } else {
            // Update name if public key already exists
            peerPublicKeys[peerIp].name = peerName;
        }
        
        const config = {
            ...currentConfig,
            peer_nodes: peerNodes,
            peer_public_keys: peerPublicKeys
        };
        
        const response = await fetch('/api/v1/peer-sync/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        
        if (!response.ok) throw new Error('Failed to add peer node');
        
        input.value = '';
        showToast('Peer node added', 'success');
        await loadPeerSyncConfig();
    } catch (error) {
        showToast('Error adding peer node: ' + error.message, 'error');
    }
}

// Remove peer node
async function removePeerNode(peerAddress) {
    try {
        const currentResponse = await fetch('/api/v1/peer-sync/config');
        const currentConfig = await currentResponse.json();
        
        const peerNodes = currentConfig.peer_nodes.filter(p => p !== peerAddress);
        const peerIp = peerAddress.split(':')[0];
        
        // Also remove peer public key if exists
        const peerPublicKeys = { ...currentConfig.peer_public_keys };
        if (peerPublicKeys[peerIp]) {
            delete peerPublicKeys[peerIp];
        }
        
        const config = {
            ...currentConfig,
            peer_nodes: peerNodes,
            peer_public_keys: peerPublicKeys
        };
        
        const response = await fetch('/api/v1/peer-sync/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        
        if (!response.ok) throw new Error('Failed to remove peer node');
        
        showToast('Peer node removed', 'success');
        await loadPeerSyncConfig();
    } catch (error) {
        showToast('Error removing peer node: ' + error.message, 'error');
    }
}

// Note: addPeerKey, savePeerKey, removePeerKey functions removed
// Peer keys are now managed together with peer nodes in addPeerNode/updatePeerKey

// Load Peer-Sync status
async function loadPeerSyncStatus() {
    try {
        const response = await fetch('/api/v1/peer-sync/status');
        if (!response.ok) throw new Error('Failed to load peer-sync status');
        const status = await response.json();
        
        // Update overview
        const overview = document.getElementById('peerSyncOverview');
        overview.innerHTML = `
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 4px; text-align: center;">
                <div style="font-size: 2em; font-weight: bold; color: #4CAF50;">${status.overview.total_successful_syncs || 0}</div>
                <div style="color: #666;">Successful Syncs</div>
            </div>
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 4px; text-align: center;">
                <div style="font-size: 2em; font-weight: bold; color: #f44336;">${status.overview.total_failed_syncs || 0}</div>
                <div style="color: #666;">Failed Syncs</div>
            </div>
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 4px; text-align: center;">
                <div style="font-size: 2em; font-weight: bold; color: #2196F3;">${status.overview.overall_success_rate || 0}%</div>
                <div style="color: #666;">Success Rate</div>
            </div>
            <div style="border: 1px solid #ddd; padding: 15px; border-radius: 4px; text-align: center;">
                <div style="font-size: 1.5em; font-weight: bold; color: #FF9800;">${status.overview.average_sync_duration_ms || 0}ms</div>
                <div style="color: #666;">Avg Sync Duration</div>
            </div>
        `;
        
        // Update peer status table
        const tbody = document.getElementById('peerStatusTableBody');
        tbody.innerHTML = '';
        status.peer_statuses.forEach(peer => {
            const row = document.createElement('tr');
            const statusBadge = peer.status === 'success' ? 
                '<span style="background-color: #4CAF50; color: white; padding: 4px 8px; border-radius: 4px;">Success</span>' :
                '<span style="background-color: #f44336; color: white; padding: 4px 8px; border-radius: 4px;">Error</span>';
            
            row.innerHTML = `
                <td style="padding: 10px; border: 1px solid #ddd;">${peer.peer_name}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${peer.peer_ip}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${statusBadge}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${peer.last_sync ? new Date(peer.last_sync).toLocaleString() : 'Never'}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${peer.success_rate}%</td>
                <td style="padding: 10px; border: 1px solid #ddd;">
                    <button class="btn btn-secondary" onclick="testPeerConnection('${peer.peer_ip}')">Test</button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
        // Update sync events table
        const eventsTbody = document.getElementById('syncEventsTableBody');
        eventsTbody.innerHTML = '';
        status.recent_events.forEach(event => {
            const row = document.createElement('tr');
            const statusBadge = event.status === 'success' ? 
                '<span style="background-color: #4CAF50; color: white; padding: 4px 8px; border-radius: 4px;">Success</span>' :
                '<span style="background-color: #f44336; color: white; padding: 4px 8px; border-radius: 4px;">Error</span>';
            
            row.innerHTML = `
                <td style="padding: 10px; border: 1px solid #ddd;">${new Date(event.timestamp).toLocaleString()}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${event.peer_name}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${statusBadge}</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${event.duration_ms}ms</td>
                <td style="padding: 10px; border: 1px solid #ddd;">${event.details || ''}</td>
            `;
            eventsTbody.appendChild(row);
        });
        
    } catch (error) {
        console.error('Error loading peer-sync status:', error);
        showToast('Error loading peer-sync status: ' + error.message, 'error');
    }
}

// Trigger manual sync
async function triggerPeerSync() {
    try {
        const response = await fetch('/api/v1/peer-sync/sync-now', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        
        if (!response.ok) throw new Error('Failed to trigger sync');
        
        const result = await response.json();
        showToast(`Sync completed: ${result.synced_peers.length} peers synced`, 'success');
        await loadPeerSyncStatus();
    } catch (error) {
        showToast('Error triggering sync: ' + error.message, 'error');
    }
}

// Test peer connection
async function testPeerConnection(peer) {
    try {
        const response = await fetch('/api/v1/peer-sync/test-connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ peer: peer })
        });
        
        if (!response.ok) throw new Error('Failed to test connection');
        
        const result = await response.json();
        showToast(`Connection test: ${result.success ? 'Success' : 'Failed'} (${result.latency_ms}ms)`, result.success ? 'success' : 'error');
        await loadPeerSyncStatus();
    } catch (error) {
        showToast('Error testing connection: ' + error.message, 'error');
    }
}

// Copy to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    showToast('Copied to clipboard', 'success');
}

// Note: addPeerPublicKey, savePeerPublicKey, removePeerPublicKey functions removed
// Replaced with: addPeerKey, savePeerKey, removePeerKey

// Load Peer-Sync config when tab is opened
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener for tab switch
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            if (targetTab === 'peer-sync') {
                loadPeerSyncConfig();
                loadPeerSyncStatus();
            }
        });
    });
});
