// Authentication JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const totpGroup = document.getElementById('totpGroup');
    const backupCodeGroup = document.getElementById('backupCodeGroup');
    const useBackupCodeLink = document.getElementById('useBackupCodeLink');
    const use2FACodeLink = document.getElementById('use2FACodeLink');
    
    // Toggle between 2FA code and backup code
    if (useBackupCodeLink) {
        useBackupCodeLink.addEventListener('click', function(e) {
            e.preventDefault();
            // Clear 2FA input when switching to backup code
            const totpInput = document.getElementById('totp');
            if (totpInput) {
                totpInput.value = '';
            }
            totpGroup.style.display = 'none';
            backupCodeGroup.style.display = 'block';
            const backupCodeInput = document.getElementById('backupCode');
            if (backupCodeInput) {
                backupCodeInput.value = ''; // Clear backup code input
                setTimeout(() => backupCodeInput.focus(), 100);
            }
        });
    }
    
    if (use2FACodeLink) {
        use2FACodeLink.addEventListener('click', function(e) {
            e.preventDefault();
            // Clear backup code input when switching to 2FA
            const backupCodeInput = document.getElementById('backupCode');
            if (backupCodeInput) {
                backupCodeInput.value = '';
            }
            backupCodeGroup.style.display = 'none';
            totpGroup.style.display = 'block';
            const totpInput = document.getElementById('totp');
            if (totpInput) {
                totpInput.value = ''; // Clear 2FA input
                setTimeout(() => totpInput.focus(), 100);
            }
        });
    }
    
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('errorMessage');
            
            // Determine which code to use based on which field is visible
            let codeToUse = null;
            if (backupCodeGroup && backupCodeGroup.style.display !== 'none') {
                // Backup code field is visible, use it
                const backupCodeInput = document.getElementById('backupCode');
                if (backupCodeInput) {
                    codeToUse = backupCodeInput.value.trim() || null;
                }
            } else if (totpGroup && totpGroup.style.display !== 'none') {
                // 2FA field is visible, use it
                const totpInput = document.getElementById('totp');
                if (totpInput) {
                    codeToUse = totpInput.value.trim() || null;
                }
            }
            
            try {
                const response = await fetch('/api/v1/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        totp_token: codeToUse
                    })
                });
                
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    errorMessage.textContent = 'Invalid response from server: ' + text.substring(0, 100);
                    errorMessage.style.display = 'block';
                    return;
                }
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    window.location.href = '/';
                } else {
                    if (data.requires_2fa) {
                        // Show 2FA input by default, but allow switching to backup code
                        // Clear both inputs when showing 2FA requirement
                        const totpInput = document.getElementById('totp');
                        const backupCodeInput = document.getElementById('backupCode');
                        if (totpInput) totpInput.value = '';
                        if (backupCodeInput) backupCodeInput.value = '';
                        
                        totpGroup.style.display = 'block';
                        backupCodeGroup.style.display = 'none';
                        errorMessage.textContent = 'Please enter your 2FA code or backup code';
                        errorMessage.className = 'error-message info';
                        errorMessage.style.display = 'block';
                        // Focus on 2FA input
                        if (totpInput) {
                            setTimeout(() => totpInput.focus(), 100);
                        }
                    } else {
                        errorMessage.textContent = data.message || 'Login failed';
                        errorMessage.className = 'error-message';
                        errorMessage.style.display = 'block';
                    }
                }
            } catch (error) {
                errorMessage.textContent = 'Login error: ' + error.message;
                errorMessage.style.display = 'block';
            }
        });
    }
    
    // Check auth status
    checkAuthStatus();
});

async function checkAuthStatus() {
    try {
        const response = await fetch('/api/v1/auth/status');
        if (!response.ok) {
            // If endpoint doesn't exist or returns error, allow access
            return;
        }
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            // Not JSON response, allow access
            return;
        }
        const data = await response.json();
        
        if (!data.authenticated && window.location.pathname !== '/login') {
            window.location.href = '/login';
        } else if (data.authenticated && window.location.pathname === '/login') {
            window.location.href = '/';
        }
    } catch (error) {
        // If there's an error, don't block access - allow the page to load
        console.log('Auth check error:', error);
    }
}

async function logout() {
    try {
        await fetch('/api/v1/auth/logout', { method: 'POST' });
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
    }
}

