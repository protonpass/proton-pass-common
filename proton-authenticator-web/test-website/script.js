// Load the WASM module using ES module imports
let worker = {};

// Function to load the WASM module
async function loadWasmModule() {
    try {
        // Dynamically import the WASM module (ES module)
        const wasmModule = await import('./pkg/worker/proton_authenticator_web.js');

        // Initialize the WASM module
        await wasmModule.default();

        // Store the module exports
        worker = wasmModule;

        // Register the logger
        if (typeof worker.register_authenticator_logger === 'function') {
            worker.register_authenticator_logger((level, message) => {
                console.log(`[${level}] ${message}`);
            });
        }

        return worker;
    } catch (error) {
        console.error('Failed to load WASM module:', error);
        throw new Error('Failed to load WASM module: ' + error.message);
    }
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
    'import_from_ente_encrypted': {
        name: 'Ente (Encrypted)',
        requiresPassword: true,
        isBinary: false
    },
    'import_from_google_qr': {
        name: 'Google QR',
        requiresPassword: false,
        isBinary: false
    },
    'import_from_google_authenticator_qr': {
        name: 'Google Authenticator QR (Image)',
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
        if (typeof worker[funcName] === 'function') {
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

// QR Code scanner instance (no longer needed - using WASM function)
// let qrCodeReader = null;

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
        
        // Initialize QR code reader (no longer needed - using WASM function)
        // if (typeof ZXingBrowser !== 'undefined') {
        //     qrCodeReader = new ZXingBrowser.BrowserQRCodeReader();
        // }
        
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
    
    // Update file input accept attribute for Google Authenticator QR (Image)
    if (importerKey === 'import_from_google_authenticator_qr') {
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

// Scan QR code from image (no longer needed - using WASM function)
// async function scanQRFromImage(file) {
//     return new Promise((resolve, reject) => {
//         if (!qrCodeReader) {
//             reject(new Error('QR code reader not initialized'));
//             return;
//         }
//         
//         const img = new Image();
//         img.onload = async () => {
//             try {
//                 const result = await qrCodeReader.decodeFromImageElement(img);
//                 resolve(result.getText());
//             } catch (error) {
//                 reject(new Error('No QR code found in image: ' + error.message));
//             }
//         };
//         img.onerror = () => reject(new Error('Failed to load image'));
//         img.src = URL.createObjectURL(file);
//     });
// }

// Handle process button click
async function handleProcess() {
    if (!selectedFile || !currentImporter) return;
    
    showLoading();
    
    try {
        // Special handling for Google Authenticator QR (Image)
        if (importerSelect.value === 'import_from_google_authenticator_qr') {
            // Read image as binary data
            const imageData = await readFile(selectedFile, true);
            
            // Convert to Uint8Array for WASM
            const uint8Array = new Uint8Array(imageData);
            
            // Use the WASM function to scan QR and import
            const result = currentImporter.func(uint8Array);
            
            if (result === undefined) {
                throw new Error('No QR code found in the image or failed to parse QR code');
            }
            
            // Display the results
            displayResults(result);
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
    
    // Remove any existing QR code value displays (no longer needed)
    const existingQrElements = document.querySelectorAll('.qr-code-value');
    existingQrElements.forEach(element => element.remove());
    
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