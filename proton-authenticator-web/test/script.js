// We'll load the WASM module by including it as a script tag
// and providing the necessary CommonJS shims
let worker = {};

// Function to load the WASM module
async function loadWasmModule() {
    return new Promise(async (resolve, reject) => {
        try {
            // First, we need to load the WASM binary
            const wasmResponse = await fetch('./pkg/worker/proton_authenticator_web_bg.wasm');
            const wasmBytes = await wasmResponse.arrayBuffer();
            
            // Create CommonJS environment
            const fakeModule = { exports: {} };
            const fakeRequire = (dep) => {
                if (dep === 'util') {
                    return { 
                        TextEncoder: globalThis.TextEncoder || window.TextEncoder,
                        TextDecoder: globalThis.TextDecoder || window.TextDecoder
                    };
                }
                if (dep === 'fs') {
                    return { 
                        readFileSync: (path) => {
                            // Return the WASM bytes we already loaded
                            return new Uint8Array(wasmBytes);
                        }
                    };
                }
                if (dep === 'path') {
                    return { join: (...args) => args.join('/') };
                }
                return {};
            };
            
            // Set up globals
            window.module = fakeModule;
            window.require = fakeRequire;
            window.__dirname = './pkg/worker';
            
            // Load the JavaScript wrapper
            const script = document.createElement('script');
            script.src = './pkg/worker/proton_authenticator_web.js';
            script.onload = () => {
                worker = fakeModule.exports;
                
                // Clean up globals
                delete window.module;
                delete window.require;
                delete window.__dirname;
                
                resolve(worker);
            };
            script.onerror = () => {
                reject(new Error('Failed to load WASM module'));
            };
            
            document.head.appendChild(script);
        } catch (error) {
            reject(error);
        }
    });
}

// Configuration for importers with metadata
const IMPORTER_METADATA = {
    'import_from_aegis_json': {
        name: 'Aegis JSON',
        requiresPassword: 'optional',
        isBinary: false
    },
    'import_from_aegis_txt': {
        name: 'Aegis TXT',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_bitwarden_json': {
        name: 'Bitwarden JSON',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_bitwarden_csv': {
        name: 'Bitwarden CSV',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_ente_txt': {
        name: 'Ente TXT',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_google_qr': {
        name: 'Google QR',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_google_qr_image': {
        name: 'Google QR (Image)',
        requiresPassword: false,
        isBinary: true
    },
    'import_from_lastpass_json': {
        name: 'LastPass JSON',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_proton_authenticator': {
        name: 'Proton Authenticator',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_proton_authenticator_with_password': {
        name: 'Proton Authenticator (with password)',
        requiresPassword: true,
        isBinary: false
    },
    'import_from_2fas': {
        name: '2FAS',
        requiresPassword: 'optional',
        isBinary: false
    },
    'import_from_pass_zip': {
        name: 'Pass ZIP',
        requiresPassword: false,
        isBinary: true
    }
};

// Dynamically discover available importers
function discoverImporters() {
    const importers = {};
    
    for (const funcName in IMPORTER_METADATA) {
        if (funcName === 'import_from_google_qr_image') {
            // Special case: this is our custom image QR scanner
            importers[funcName] = {
                ...IMPORTER_METADATA[funcName],
                func: null // Will be handled specially in handleProcess
            };
        } else if (typeof worker[funcName] === 'function') {
            importers[funcName] = {
                ...IMPORTER_METADATA[funcName],
                func: worker[funcName]
            };
        }
    }
    
    return importers;
}

// Get available importers (will be populated after module loads)
let IMPORTERS = {};

// QR Code scanner instance
let qrCodeReader = null;

// Utility function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// DOM elements
const importerSelect = document.getElementById('importer-select');
const passwordGroup = document.getElementById('password-group');
const passwordInput = document.getElementById('password');
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileSelectBtn = document.getElementById('file-select-btn');
const fileInfo = document.getElementById('file-info');
const fileName = document.getElementById('file-name');
const fileSize = document.getElementById('file-size');
const fileType = document.getElementById('file-type');
const processBtn = document.getElementById('process-btn');
const clearBtn = document.getElementById('clear-btn');
const results = document.getElementById('results');
const entriesCount = document.getElementById('entries-count');
const errorsCount = document.getElementById('errors-count');
const entriesContainer = document.getElementById('entries-container');
const errorsContainer = document.getElementById('errors-container');
const loading = document.getElementById('loading');

// State
let selectedFile = null;
let currentImporter = null;

// Initialize the application
async function initialize() {
    try {
        // Load the WASM module first
        await loadWasmModule();
        
        // Discover available importers
        IMPORTERS = discoverImporters();
        
        // Initialize QR code reader
        if (typeof ZXingBrowser !== 'undefined') {
            qrCodeReader = new ZXingBrowser.BrowserQRCodeReader();
        }
        
        // Now set up the UI
        setupEventListeners();
        populateImporterSelect();
    } catch (error) {
        console.error('Failed to initialize:', error);
        alert('Failed to load the WASM module. Please refresh the page.');
    }
}

// Populate the importer select dropdown dynamically
function populateImporterSelect() {
    // Clear existing options except the first one
    while (importerSelect.children.length > 1) {
        importerSelect.removeChild(importerSelect.lastChild);
    }
    
    // Add options for each importer
    Object.entries(IMPORTERS).forEach(([key, config]) => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = config.name;
        importerSelect.appendChild(option);
    });
}

// Setup event listeners
function setupEventListeners() {
    importerSelect.addEventListener('change', handleImporterChange);
    fileSelectBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);
    dropZone.addEventListener('dragover', handleDragOver);
    dropZone.addEventListener('dragleave', handleDragLeave);
    dropZone.addEventListener('drop', handleDrop);
    processBtn.addEventListener('click', handleProcess);
    clearBtn.addEventListener('click', handleClear);
}

// Handle importer selection change
function handleImporterChange(event) {
    const importerKey = event.target.value;
    currentImporter = importerKey ? IMPORTERS[importerKey] : null;
    
    // Show/hide password field based on importer requirements
    if (currentImporter && (currentImporter.requiresPassword === true || currentImporter.requiresPassword === 'optional')) {
        passwordGroup.style.display = 'block';
        passwordInput.required = currentImporter.requiresPassword === true;
    } else {
        passwordGroup.style.display = 'none';
        passwordInput.required = false;
        passwordInput.value = '';
    }
    
    // Update file input accept attribute for Google QR (Image)
    if (importerKey === 'import_from_google_qr_image') {
        fileInput.accept = 'image/*';
    } else {
        fileInput.accept = '';
    }
    
    updateProcessButton();
}

// Handle file selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        setSelectedFile(file);
    }
}

// Handle drag over
function handleDragOver(event) {
    event.preventDefault();
    dropZone.classList.add('dragover');
}

// Handle drag leave
function handleDragLeave(event) {
    event.preventDefault();
    dropZone.classList.remove('dragover');
}

// Handle drop
function handleDrop(event) {
    event.preventDefault();
    dropZone.classList.remove('dragover');
    
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        setSelectedFile(files[0]);
    }
}

// Set selected file
function setSelectedFile(file) {
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileType.textContent = file.type || 'Unknown';
    fileInfo.style.display = 'block';
    updateProcessButton();
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Update process button state
function updateProcessButton() {
    const hasFile = selectedFile !== null;
    const hasImporter = currentImporter !== null;
    const hasRequiredPassword = !currentImporter || 
                               currentImporter.requiresPassword !== true || 
                               passwordInput.value.trim() !== '';
    
    processBtn.disabled = !(hasFile && hasImporter && hasRequiredPassword);
}

// Scan QR code from image
async function scanQRFromImage(file) {
    return new Promise((resolve, reject) => {
        if (!qrCodeReader) {
            reject(new Error('QR code reader not initialized'));
            return;
        }
        
        const img = new Image();
        img.onload = async () => {
            try {
                const result = await qrCodeReader.decodeFromImageElement(img);
                resolve(result.getText());
            } catch (error) {
                reject(new Error('No QR code found in image: ' + error.message));
            }
        };
        img.onerror = () => reject(new Error('Failed to load image'));
        img.src = URL.createObjectURL(file);
    });
}

// Handle process button click
async function handleProcess() {
    if (!selectedFile || !currentImporter) return;
    
    showLoading();
    
    try {
        // Special handling for Google QR (Image)
        if (importerSelect.value === 'import_from_google_qr_image') {
            // Scan QR code from image
            const qrCodeText = await scanQRFromImage(selectedFile);
            
            // Display the QR code value for testing
            console.log('QR Code Value:', qrCodeText);
            
            // Add QR code value to results for display
            const qrDisplayElement = document.createElement('div');
            qrDisplayElement.className = 'qr-code-value';
            qrDisplayElement.innerHTML = `<strong>QR Code Detected:</strong><br>${escapeHtml(qrCodeText)}`;
            
            // Insert before results section
            const resultsSection = document.getElementById('results');
            if (resultsSection.firstChild) {
                resultsSection.insertBefore(qrDisplayElement, resultsSection.firstChild);
            } else {
                resultsSection.appendChild(qrDisplayElement);
            }
            
            // Process the QR code text using the regular Google QR importer
            if (worker.import_from_google_qr) {
                const result = worker.import_from_google_qr(qrCodeText);
                displayResults(result);
            } else {
                throw new Error('Google QR importer not available');
            }
        } else {
            // Regular processing for other importers
            const content = await readFile(selectedFile, currentImporter.isBinary);
            const password = passwordInput.value.trim() || null;
            
            let result;
            if (currentImporter.requiresPassword === true) {
                result = currentImporter.func(content, password);
            } else if (currentImporter.requiresPassword === 'optional') {
                result = currentImporter.func(content, password);
            } else {
                result = currentImporter.func(content);
            }
            
            displayResults(result);
        }
    } catch (error) {
        displayError(error);
    } finally {
        hideLoading();
    }
}

// Read file content
function readFile(file, isBinary) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = (event) => {
            if (isBinary) {
                resolve(new Uint8Array(event.target.result));
            } else {
                resolve(event.target.result);
            }
        };
        
        reader.onerror = () => reject(new Error('Failed to read file'));
        
        if (isBinary) {
            reader.readAsArrayBuffer(file);
        } else {
            reader.readAsText(file);
        }
    });
}

// Display results
function displayResults(result) {
    entriesCount.textContent = result.entries.length;
    errorsCount.textContent = result.errors.length;
    
    // Clear previous results
    entriesContainer.innerHTML = '';
    errorsContainer.innerHTML = '';
    
    // Remove any existing QR code value displays (except for newly added ones)
    const existingQrElements = document.querySelectorAll('.qr-code-value');
    if (existingQrElements.length > 1) {
        // Keep only the first one (newly added) and remove the rest
        for (let i = 1; i < existingQrElements.length; i++) {
            existingQrElements[i].remove();
        }
    }
    
    // Display entries
    result.entries.forEach((entry, index) => {
        const entryElement = createEntryElement(entry, index);
        entriesContainer.appendChild(entryElement);
    });
    
    // Display errors
    result.errors.forEach((error, index) => {
        const errorElement = createErrorElement(error, index);
        errorsContainer.appendChild(errorElement);
    });
    
    results.style.display = 'block';
}

// Create entry element
function createEntryElement(entry, index) {
    const div = document.createElement('div');
    div.className = 'entry-item';
    
    div.innerHTML = `
        <h4>Entry ${index + 1}</h4>
        <div class="entry-detail">
            <span class="label">ID:</span>
            <span class="value">${entry.id}</span>
        </div>
        <div class="entry-detail">
            <span class="label">Name:</span>
            <span class="value">${entry.name}</span>
        </div>
        <div class="entry-detail">
            <span class="label">Issuer:</span>
            <span class="value">${entry.issuer}</span>
        </div>
        <div class="entry-detail">
            <span class="label">Type:</span>
            <span class="value">${entry.entry_type}</span>
        </div>
        <div class="entry-detail">
            <span class="label">Period:</span>
            <span class="value">${entry.period}s</span>
        </div>
        <div class="entry-detail">
            <span class="label">Secret:</span>
            <span class="value">${entry.secret}</span>
        </div>
        <div class="entry-detail">
            <span class="label">URI:</span>
            <span class="value">${entry.uri}</span>
        </div>
        ${entry.note ? `
        <div class="entry-detail">
            <span class="label">Note:</span>
            <span class="value">${entry.note}</span>
        </div>
        ` : ''}
    `;
    
    return div;
}

// Create error element
function createErrorElement(error, index) {
    const div = document.createElement('div');
    div.className = 'error-item';
    
    div.innerHTML = `
        <div class="context">Error ${index + 1}: ${error.context}</div>
        <div class="message">${error.message}</div>
    `;
    
    return div;
}

// Display error
function displayError(error) {
    const errorResult = {
        entries: [],
        errors: [{
            context: 'Processing Error',
            message: error.message || 'An unknown error occurred'
        }]
    };
    
    displayResults(errorResult);
}

// Show loading
function showLoading() {
    loading.style.display = 'block';
    results.style.display = 'none';
}

// Hide loading
function hideLoading() {
    loading.style.display = 'none';
}

// Handle clear button click
function handleClear() {
    selectedFile = null;
    currentImporter = null;
    importerSelect.value = '';
    passwordInput.value = '';
    fileInput.value = '';
    fileInfo.style.display = 'none';
    results.style.display = 'none';
    passwordGroup.style.display = 'none';
    
    // Remove any QR code value displays
    const qrDisplayElements = document.querySelectorAll('.qr-code-value');
    qrDisplayElements.forEach(element => element.remove());
    
    updateProcessButton();
}

// Listen for password input changes
passwordInput.addEventListener('input', updateProcessButton);

// Initialize the application
initialize(); 