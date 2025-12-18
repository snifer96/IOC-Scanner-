class IOCScannerApp {
    constructor() {
        this.scanResults = [];
        this.currentChart = null;
        this.cacheStats = { hits: 0, size: 0 };
        this.scanHistory = [];
        this.initializeApp();
    }

    initializeApp() {
        this.bindEvents();
        this.checkApiStatus();
        this.loadHistory();
        this.setupDragAndDrop();
        this.updateSummary();
    }

    bindEvents() {
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target));
        });

        // Scan buttons
        document.getElementById('scan-btn').addEventListener('click', () => this.performSingleScan());
        document.getElementById('ioc-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSingleScan();
        });

        // Batch scan
        document.getElementById('batch-scan-btn').addEventListener('click', () => this.performBatchScan());

        // File operations
        document.getElementById('calculate-hash-btn').addEventListener('click', () => this.calculateFileHash());

        // Export buttons
        document.querySelectorAll('.btn-export').forEach(btn => {
            btn.addEventListener('click', (e) => this.exportResults(e.target.dataset.format));
        });

        // Cache management
        document.getElementById('clear-cache-btn').addEventListener('click', () => this.clearCache());

        // Results management
        document.getElementById('clear-results').addEventListener('click', () => this.clearResults());
        document.getElementById('view-report').addEventListener('click', () => window.open('/report', '_blank'));

        // Footer links
        document.getElementById('view-history').addEventListener('click', (e) => {
            e.preventDefault();
            this.showHistory();
        });

        // Modal close buttons
        document.querySelectorAll('.close-modal').forEach(btn => {
            btn.addEventListener('click', () => this.closeModal(btn.closest('.modal')));
        });

        // Close modal on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeModal(modal);
            });
        });

        // Check API status every 30 seconds
        setInterval(() => this.checkApiStatus(), 30000);
    }

    setupDragAndDrop() {
        const dropArea = document.getElementById('file-drop-area');
        const fileInput = document.getElementById('file-input');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, unhighlight, false);
        });

        function highlight() {
            dropArea.style.borderColor = '#3498db';
            dropArea.style.background = '#e3f2fd';
        }

        function unhighlight() {
            dropArea.style.borderColor = '#dee2e6';
            dropArea.style.background = '#f8f9fa';
        }

        dropArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            this.updateFileInfo(files[0]);
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                this.updateFileInfo(e.target.files[0]);
            }
        });
    }

    updateFileInfo(file) {
        const fileInfo = document.getElementById('file-info');
        if (file) {
            fileInfo.innerHTML = `
                <strong>Selected File:</strong> ${file.name}<br>
                <strong>Size:</strong> ${this.formatFileSize(file.size)}<br>
                <strong>Type:</strong> ${file.type || 'Unknown'}
            `;
        } else {
            fileInfo.innerHTML = '';
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    switchTab(button) {
        const tabId = button.dataset.tab;
        
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Show active tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
            if (content.id === `${tabId}-tab`) {
                content.classList.add('active');
            }
        });
    }

    async checkApiStatus() {
        const statusIndicator = document.getElementById('api-status-indicator');
        const startTime = Date.now();
        
        try {
            const response = await fetch('/');
            const endTime = Date.now();
            const responseTime = endTime - startTime;
            
            document.getElementById('response-time').textContent = responseTime;
            
            if (response.ok) {
                statusIndicator.innerHTML = '<i class="fas fa-circle"></i> API Status: Connected';
                statusIndicator.className = 'status-indicator connected';
            }
        } catch (error) {
            statusIndicator.innerHTML = '<i class="fas fa-circle"></i> API Status: Disconnected';
            statusIndicator.className = 'status-indicator disconnected';
        }
    }

    async performSingleScan() {
        const scanType = document.getElementById('scan-type').value;
        const iocValue = document.getElementById('ioc-input').value.trim();
        
        if (!iocValue) {
            this.showMessage('Please enter a value to scan', 'error');
            return;
        }

        this.showLoading();
        
        try {
            const startTime = Date.now();
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    type: scanType,
                    value: iocValue
                })
            });

            const result = await response.json();
            const endTime = Date.now();
            
            // Update response time
            document.getElementById('response-time').textContent = endTime - startTime;
            
            if (result.status === 'success') {
                this.addResult(result.data);
                this.updateChart();
                this.updateSummary();
                this.saveToHistory(scanType, iocValue, result);
                
                // Clear input after successful scan
                if (scanType !== 'hash') {
                    document.getElementById('ioc-input').value = '';
                }
            } else if (result.status === 'pending') {
                this.showMessage(result.message, 'warning');
            } else {
                this.showMessage(result.message || 'Scan failed', 'error');
            }
        } catch (error) {
            this.showMessage('Network error: ' + error.message, 'error');
        }
    }

    async performBatchScan() {
        const iocsText = document.getElementById('batch-iocs').value.trim();
        
        if (!iocsText) {
            this.showMessage('Please enter IOCs to scan', 'error');
            return;
        }

        const iocLines = iocsText.split('\n').filter(line => line.trim());
        const iocs = [];
        
        for (const line of iocsText.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            
            const parts = trimmed.split(':').map(p => p.trim());
            if (parts.length >= 2) {
                const type = parts[0].toLowerCase();
                const value = parts.slice(1).join(':');
                if (['ip', 'domain', 'hash', 'url'].includes(type)) {
                    iocs.push({ type, value });
                }
            }
        }

        if (iocs.length === 0) {
            this.showMessage('No valid IOCs found. Use format: type:value', 'error');
            return;
        }

        this.showLoading();
        
        try {
            const response = await fetch('/batch_scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ iocs })
            });

            const result = await response.json();
            
            if (result.status === 'success') {
                result.results.forEach(res => {
                    if (res.status === 'success') {
                        this.addResult(res.data);
                    } else {
                        this.showMessage(`Error for ${res.data?.value || 'unknown'}: ${res.message}`, 'error');
                    }
                });
                
                this.updateChart();
                this.updateSummary();
            } else {
                this.showMessage(result.message, 'error');
            }
        } catch (error) {
            this.showMessage('Network error: ' + error.message, 'error');
        }
    }

    async calculateFileHash() {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showMessage('Please select a file first', 'error');
            return;
        }

        this.showLoading();
        
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/calculate_hash', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (result.status === 'success') {
                this.displayHashResult(result);
            } else {
                this.showMessage(result.message, 'error');
            }
        } catch (error) {
            this.showMessage('Network error: ' + error.message, 'error');
        }
    }

    addResult(data) {
        const template = document.getElementById('result-template');
        const clone = template.content.cloneNode(true);
        
        const resultItem = clone.querySelector('.result-item');
        const resultType = clone.querySelector('.result-type-badge');
        const resultTitle = clone.querySelector('.result-title');
        const resultValue = clone.querySelector('.result-value');
        const resultThreat = clone.querySelector('.result-threat');
        
        // Set basic information
        const threatLevel = this.getThreatLevel(data);
        resultType.dataset.type = data.type.toLowerCase().replace(' ', '-');
        resultType.innerHTML = this.getTypeIcon(data.type);
        resultTitle.textContent = data.type;
        resultValue.textContent = data.value;
        // Special handling for URLs - show the actual URL instead of hash
if (data.type === 'URL' && data.original_url) {
    resultValue.textContent = data.original_url;
    // Optionally add a tooltip with the hash
    resultValue.title = `URL ID: ${data.url_id || data.value}`;
}
        resultThreat.textContent = threatLevel;
        resultThreat.className = `result-threat ${threatLevel.toLowerCase()}`;
        
        // Set circle chart
        const maliciousPercent = (data.malicious / data.total_engines) * 100 || 0;
        const circle = clone.querySelector('.circle-progress');
        const circleValue = clone.querySelector('.circle-value');
        const circumference = 2 * Math.PI * 25;
        const offset = circumference - (maliciousPercent / 100) * circumference;
        
        circle.style.strokeDasharray = circumference;
        circle.style.strokeDashoffset = offset;
        circleValue.textContent = `${Math.round(maliciousPercent)}%`;
        
        // Set other stats
        clone.querySelector('.suspicious').textContent = data.suspicious;
        clone.querySelector('.harmless').textContent = data.harmless;
        clone.querySelector('.undetected').textContent = data.undetected;
        clone.querySelector('.total-engines').textContent = data.total_engines;
        clone.querySelector('.last-analysis').textContent = data.last_analysis_date;
        clone.querySelector('.reputation').textContent = data.reputation;
        
        // Add event listeners
        clone.querySelector('.view-details').addEventListener('click', () => {
            this.showDetails(data);
        });
        
        clone.querySelector('.copy-value').addEventListener('click', () => {
            navigator.clipboard.writeText(data.value)
                .then(() => this.showMessage('Copied to clipboard!', 'success'))
                .catch(err => this.showMessage('Failed to copy: ' + err, 'error'));
        });
        
        clone.querySelector('.rescan').addEventListener('click', () => {
            const scanType = data.type.toLowerCase().replace(' ', '');
            document.getElementById('scan-type').value = scanType;
            document.getElementById('ioc-input').value = data.value;
            this.switchTab(document.querySelector('[data-tab="single"]'));
            this.performSingleScan();
        });
        
        // Remove placeholder if it exists
        const placeholder = document.querySelector('.placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        // Add to results container
        const resultsContainer = document.getElementById('results-container');
        resultsContainer.insertBefore(clone, resultsContainer.firstChild);
        
        // Add to results array
        this.scanResults.unshift({
            status: 'success',
            data: data,
            timestamp: new Date().toISOString()
        });
    }

    displayHashResult(data) {
        const template = document.getElementById('result-template');
        const clone = template.content.cloneNode(true);
        
        const resultItem = clone.querySelector('.result-item');
        const resultType = clone.querySelector('.result-type-badge');
        const resultTitle = clone.querySelector('.result-title');
        const resultValue = clone.querySelector('.result-value');
        const resultThreat = clone.querySelector('.result-threat');
        
        // Set basic information
        resultType.dataset.type = 'hash';
        resultType.innerHTML = '<i class="fas fa-fingerprint"></i>';
        resultTitle.textContent = 'FILE HASHES';
        resultValue.textContent = data.filename;
        resultThreat.textContent = 'INFO';
        resultThreat.className = 'result-threat low';
        
        // Remove circle chart and replace with hash list
        const resultStats = clone.querySelector('.result-stats');
        resultStats.innerHTML = `
            <div class="hash-list">
                <div class="hash-item">
                    <strong>MD5:</strong> 
                    <code class="hash-value">${data.hashes.md5}</code>
                    <button class="btn-action copy-hash" data-hash="${data.hashes.md5}">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                <div class="hash-item">
                    <strong>SHA-1:</strong> 
                    <code class="hash-value">${data.hashes.sha1}</code>
                    <button class="btn-action copy-hash" data-hash="${data.hashes.sha1}">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                <div class="hash-item">
                    <strong>SHA-256:</strong> 
                    <code class="hash-value">${data.hashes.sha256}</code>
                    <button class="btn-action copy-hash" data-hash="${data.hashes.sha256}">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>
        `;
        
        // Update meta info
        const resultMeta = clone.querySelector('.result-meta');
        resultMeta.innerHTML = `
            <span><i class="far fa-file"></i> Size: ${this.formatFileSize(data.size)}</span>
        `;
        
        // Update actions
        const resultActions = clone.querySelector('.result-actions');
        resultActions.innerHTML = `
            <button class="btn-action scan-md5" data-hash="${data.hashes.md5}">
                <i class="fas fa-search"></i> Scan MD5
            </button>
            <button class="btn-action scan-sha1" data-hash="${data.hashes.sha1}">
                <i class="fas fa-search"></i> Scan SHA-1
            </button>
            <button class="btn-action scan-sha256" data-hash="${data.hashes.sha256}">
                <i class="fas fa-search"></i> Scan SHA-256
            </button>
        `;
        
        // Add event listeners for copy buttons
        clone.querySelectorAll('.copy-hash').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const hash = e.target.closest('button').dataset.hash;
                navigator.clipboard.writeText(hash)
                    .then(() => this.showMessage('Hash copied to clipboard!', 'success'))
                    .catch(err => this.showMessage('Failed to copy: ' + err, 'error'));
            });
        });
        
        // Add event listeners for scan buttons
        clone.querySelector('.scan-sha256').addEventListener('click', (e) => {
            const hash = e.target.closest('button').dataset.hash;
            document.getElementById('scan-type').value = 'hash';
            document.getElementById('ioc-input').value = hash;
            this.switchTab(document.querySelector('[data-tab="single"]'));
            this.performSingleScan();
        });
        
        clone.querySelector('.scan-md5').addEventListener('click', (e) => {
            const hash = e.target.closest('button').dataset.hash;
            document.getElementById('scan-type').value = 'hash';
            document.getElementById('ioc-input').value = hash;
            this.switchTab(document.querySelector('[data-tab="single"]'));
            this.performSingleScan();
        });
        
        clone.querySelector('.scan-sha1').addEventListener('click', (e) => {
            const hash = e.target.closest('button').dataset.hash;
            document.getElementById('scan-type').value = 'hash';
            document.getElementById('ioc-input').value = hash;
            this.switchTab(document.querySelector('[data-tab="single"]'));
            this.performSingleScan();
        });
        
        // Remove placeholder if it exists
        const placeholder = document.querySelector('.placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        // Add to results container
        const resultsContainer = document.getElementById('results-container');
        resultsContainer.insertBefore(clone, resultsContainer.firstChild);
    }

    getTypeIcon(type) {
        const icons = {
            'IP Address': 'fa-network-wired',
            'Domain': 'fa-globe',
            'File Hash': 'fa-fingerprint',
            'URL': 'fa-link'
        };
        return `<i class="fas ${icons[type] || 'fa-question'}"></i>`;
    }

    getThreatLevel(data) {
        if (data.malicious > 0) return 'High';
        if (data.suspicious > 0) return 'Medium';
        if (data.harmless > 0) return 'Low';
        return 'Unknown';
    }

    updateChart() {
        const ctx = document.getElementById('stats-chart').getContext('2d');
        
        // Prepare data
        const labels = this.scanResults.slice(0, 10).map((r, i) => `Scan ${i + 1}`);
        const malicious = this.scanResults.slice(0, 10).map(r => r.data?.malicious || 0);
        const suspicious = this.scanResults.slice(0, 10).map(r => r.data?.suspicious || 0);
        
        if (this.currentChart) {
            this.currentChart.destroy();
        }
        
        this.currentChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Malicious',
                        data: malicious,
                        backgroundColor: '#e74c3c',
                        borderColor: '#c0392b',
                        borderWidth: 1
                    },
                    {
                        label: 'Suspicious',
                        data: suspicious,
                        backgroundColor: '#f39c12',
                        borderColor: '#d68910',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Last 10 Scans - Detection Results'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Detections'
                        }
                    }
                }
            }
        });
    }

    updateSummary() {
        const total = this.scanResults.length;
        const high = this.scanResults.filter(r => this.getThreatLevel(r.data) === 'High').length;
        const medium = this.scanResults.filter(r => this.getThreatLevel(r.data) === 'Medium').length;
        const low = this.scanResults.filter(r => this.getThreatLevel(r.data) === 'Low').length;
        
        document.getElementById('total-scans').textContent = total;
        document.getElementById('high-threats').textContent = high;
        document.getElementById('medium-threats').textContent = medium;
        document.getElementById('low-threats').textContent = low;
        
        // Update header counts
        document.getElementById('scan-count').textContent = total;
        document.getElementById('cache-count').textContent = Object.keys(this.cacheStats).length;
    }

    async exportResults(format) {
        if (this.scanResults.length === 0) {
            this.showMessage('No results to export', 'warning');
            return;
        }

        this.showMessage('Exporting...', 'info');
        
        try {
            const response = await fetch('/export', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    results: this.scanResults,
                    format: format
                })
            });

            if (response.ok) {
                // Create download link
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                if (format === 'all') {
                    a.download = `ioc_scan_full_report_${timestamp}.zip`;
                } else {
                    a.download = `ioc_scan_${format}_${timestamp}.${format}`;
                }
                
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                this.showMessage(`Exported successfully as ${format.toUpperCase()}`, 'success');
            } else {
                const error = await response.json();
                this.showMessage(`Export failed: ${error.message}`, 'error');
            }
        } catch (error) {
            this.showMessage('Export error: ' + error.message, 'error');
        }
    }

    async clearCache() {
        try {
            const response = await fetch('/clear_cache', {
                method: 'POST'
            });
            
            const result = await response.json();
            if (result.status === 'success') {
                this.showMessage('Cache cleared successfully', 'success');
                this.cacheStats = { hits: 0, size: 0 };
                this.updateSummary();
            }
        } catch (error) {
            this.showMessage('Failed to clear cache: ' + error.message, 'error');
        }
    }

    clearResults() {
        this.scanResults = [];
        document.getElementById('results-container').innerHTML = `
            <div class="placeholder">
                <i class="fas fa-search fa-3x"></i>
                <p>Scan results will appear here</p>
                <small>Use the scanner on the left to start</small>
            </div>
        `;
        this.updateSummary();
        this.updateChart();
        this.showMessage('Results cleared', 'info');
    }

    showDetails(data) {
        const modal = document.getElementById('details-modal');
        const modalContent = document.getElementById('modal-content');
        
        modalContent.textContent = JSON.stringify(data.raw_data, null, 2);
        modal.style.display = 'block';
    }

    async showHistory() {
        try {
            const response = await fetch('/history');
            const result = await response.json();
            
            if (result.status === 'success') {
                const modal = document.getElementById('history-modal');
                const historyContent = document.getElementById('history-content');
                
                let html = '<div class="history-list">';
                result.history.forEach((item, index) => {
                    html += `
                        <div class="history-item">
                            <div class="history-header">
                                <span class="history-type">${item.type.toUpperCase()}</span>
                                <span class="history-time">${new Date(item.timestamp).toLocaleString()}</span>
                            </div>
                            <div class="history-value">${item.value}</div>
                            <div class="history-status">${item.result.status}</div>
                        </div>
                    `;
                });
                html += '</div>';
                
                historyContent.innerHTML = html;
                modal.style.display = 'block';
            }
        } catch (error) {
            this.showMessage('Failed to load history: ' + error.message, 'error');
        }
    }

    saveToHistory(type, value, result) {
        this.scanHistory.push({
            type: type,
            value: value,
            result: result,
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 100 items
        if (this.scanHistory.length > 100) {
            this.scanHistory.shift();
        }
        
        // Save to localStorage
        localStorage.setItem('iocScannerHistory', JSON.stringify(this.scanHistory));
    }

    loadHistory() {
        try {
            const saved = localStorage.getItem('iocScannerHistory');
            if (saved) {
                this.scanHistory = JSON.parse(saved);
            }
        } catch (error) {
            console.error('Failed to load history:', error);
        }
    }

    showLoading() {
        const resultsContainer = document.getElementById('results-container');
        if (!document.querySelector('.loading')) {
            resultsContainer.innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    <p>Scanning... Please wait</p>
                </div>
            `;
        }
    }

    showMessage(message, type) {
        const statusDiv = document.getElementById('export-status');
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.innerHTML = `
            <i class="fas fa-${this.getMessageIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        statusDiv.innerHTML = '';
        statusDiv.appendChild(messageDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (messageDiv.parentNode === statusDiv) {
                statusDiv.removeChild(messageDiv);
            }
        }, 5000);
    }

    getMessageIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    closeModal(modal) {
        modal.style.display = 'none';
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.scannerApp = new IOCScannerApp();
});