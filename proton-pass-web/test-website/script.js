import init, { find_duplicate_items_wasm } from "./pkg/duplicate/proton_pass_web.js";

const FIELD_TYPES = ["Text", "Hidden", "Totp", "Timestamp"];

let items = [];
let nextId = 1;
let editingItemId = null;

const itemTypeSelect = document.getElementById("item-type");
const itemsTableBody = document.getElementById("items-table-body");
const itemCountEl = document.getElementById("item-count");
const itemsEmptyState = document.getElementById("items-empty-state");
const resultsPanel = document.getElementById("results-panel");
const resultsContent = document.getElementById("results-content");
const statusBanner = document.getElementById("status-banner");
const customFieldsList = document.getElementById("custom-fields-list");
const extraFieldsList = document.getElementById("extra-fields-list");
const importJsonInput = document.getElementById("import-json-input");
const addItemHeading = document.getElementById("add-item-heading");
const addItemBtn = document.getElementById("add-item-btn");
const cancelEditBtn = document.getElementById("cancel-edit-btn");
const viewDialog = document.getElementById("view-item-dialog");
const viewItemJson = document.getElementById("view-item-json");

function showStatus(message, isError) {
    statusBanner.textContent = message;
    statusBanner.classList.toggle("status-error", Boolean(isError));
    statusBanner.hidden = false;
}

function hideStatus() {
    statusBanner.hidden = true;
}

function nextItemId() {
    return `item-${nextId++}`;
}

function linesOf(textareaId) {
    return document
        .getElementById(textareaId)
        .value.split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
}

function value(id) {
    return document.getElementById(id).value;
}

function setValue(id, newValue) {
    document.getElementById(id).value = newValue ?? "";
}

function addDynamicFieldRow(container, initial = {}) {
    const row = document.createElement("div");
    row.className = "dynamic-field-row";

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "Field name";
    nameInput.className = "field-name";
    nameInput.value = initial.name ?? "";

    const typeSelect = document.createElement("select");
    typeSelect.className = "field-type";
    for (const fieldType of FIELD_TYPES) {
        const option = document.createElement("option");
        option.value = fieldType;
        option.textContent = fieldType;
        typeSelect.appendChild(option);
    }
    typeSelect.value = initial.type ?? "Text";

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.placeholder = typeSelect.value === "Timestamp" ? "Unix timestamp (seconds)" : "Field value";
    valueInput.className = "field-value";
    valueInput.value = initial.value ?? "";

    typeSelect.addEventListener("change", () => {
        valueInput.placeholder = typeSelect.value === "Timestamp" ? "Unix timestamp (seconds)" : "Field value";
    });

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "remove-field-btn";
    removeBtn.textContent = "×";
    removeBtn.addEventListener("click", () => row.remove());

    row.append(nameInput, typeSelect, valueInput, removeBtn);
    container.appendChild(row);
}

document.getElementById("add-custom-field-btn").addEventListener("click", () => {
    addDynamicFieldRow(customFieldsList);
});

document.getElementById("add-extra-field-btn").addEventListener("click", () => {
    addDynamicFieldRow(extraFieldsList);
});

function readDynamicFields(container) {
    return Array.from(container.querySelectorAll(".dynamic-field-row"))
        .map((row) => ({
            name: row.querySelector(".field-name").value,
            type: row.querySelector(".field-type").value,
            value: row.querySelector(".field-value").value,
        }))
        .filter((field) => field.name.length > 0)
        .map((field) => ({
            name: field.name,
            content: field.type === "Timestamp" ? { Timestamp: Number(field.value) || 0 } : { [field.type]: field.value },
        }));
}

function populateDynamicFields(container, fields) {
    container.innerHTML = "";
    for (const field of fields ?? []) {
        const [type, fieldValue] = Object.entries(field.content)[0];
        addDynamicFieldRow(container, { name: field.name, type, value: String(fieldValue) });
    }
}

itemTypeSelect.addEventListener("change", () => {
    const selected = itemTypeSelect.value;
    document.querySelectorAll(".type-fields").forEach((fieldset) => {
        fieldset.hidden = fieldset.dataset.type !== selected;
    });
});

function emptyIdentity(overrides) {
    return {
        full_name: "",
        email: "",
        phone_number: "",
        first_name: "",
        middle_name: "",
        last_name: "",
        birthdate: "",
        gender: "",
        extra_personal_details: [],
        organization: "",
        street_address: "",
        zip_or_postal_code: "",
        city: "",
        state_or_province: "",
        country_or_region: "",
        floor: "",
        county: "",
        extra_address_details: [],
        social_security_number: "",
        passport_number: "",
        license_number: "",
        website: "",
        x_handle: "",
        second_phone_number: "",
        linkedin: "",
        reddit: "",
        facebook: "",
        yahoo: "",
        instagram: "",
        extra_contact_details: [],
        company: "",
        job_title: "",
        personal_website: "",
        work_phone_number: "",
        work_email: "",
        extra_work_details: [],
        extra_sections: [],
        ...overrides,
    };
}

function buildContent(type) {
    switch (type) {
        case "Login":
            return {
                Login: {
                    email: value("login-email"),
                    username: value("login-username"),
                    password: value("login-password"),
                    urls: linesOf("login-urls"),
                    totp_uri: "",
                    passkeys: [],
                    autofill_urls: [],
                },
            };
        case "Note":
            return { Note: null };
        case "Alias":
            return { Alias: null };
        case "CreditCard":
            return {
                CreditCard: {
                    cardholder_name: value("cc-cardholder"),
                    card_type: value("cc-type"),
                    number: value("cc-number"),
                    verification_number: value("cc-verification"),
                    expiration_date: value("cc-expiration"),
                    pin: value("cc-pin"),
                },
            };
        case "Identity":
            return {
                Identity: emptyIdentity({
                    full_name: value("identity-full-name"),
                    email: value("identity-email"),
                    phone_number: value("identity-phone"),
                    organization: value("identity-organization"),
                }),
            };
        case "SshKey":
            return {
                SshKey: {
                    private_key: value("ssh-private-key"),
                    public_key: value("ssh-public-key"),
                    sections: [],
                },
            };
        case "Wifi":
            return {
                Wifi: {
                    ssid: value("wifi-ssid"),
                    password: value("wifi-password"),
                    security: value("wifi-security"),
                    sections: [],
                },
            };
        case "Custom":
            return {
                Custom: {
                    sections: [
                        {
                            section_name: value("custom-section-name"),
                            section_fields: readDynamicFields(customFieldsList),
                        },
                    ],
                },
            };
        default:
            throw new Error(`Unknown item type: ${type}`);
    }
}

function summarize(item) {
    const [variant, payload] = Object.entries(item.content)[0];
    switch (variant) {
        case "Login":
            return `${payload.username || payload.email || "(no identity)"} / ${"•".repeat(
                Math.min(payload.password.length, 8)
            )}`;
        case "CreditCard":
            return payload.number ? `card ending ${payload.number.slice(-4)}` : "(no number)";
        case "Identity":
            return payload.full_name || payload.email || "(empty)";
        case "SshKey":
            return payload.public_key ? "has public key" : "(empty)";
        case "Wifi":
            return `${payload.ssid || "(no ssid)"} / ${payload.security}`;
        case "Custom":
            return payload.sections.map((s) => s.section_name).join(", ") || "(no sections)";
        default:
            return "";
    }
}

function clearAddItemForm() {
    setValue("item-id", "");
    setValue("item-title", "");
    setValue("item-note", "");

    [
        "login-username",
        "login-email",
        "login-password",
        "login-urls",
        "cc-cardholder",
        "cc-number",
        "cc-verification",
        "cc-expiration",
        "cc-pin",
        "identity-full-name",
        "identity-email",
        "identity-phone",
        "identity-organization",
        "ssh-public-key",
        "ssh-private-key",
        "wifi-ssid",
        "wifi-password",
    ].forEach((id) => setValue(id, ""));

    setValue("cc-type", "Unspecified");
    setValue("wifi-security", "UnspecifiedWifiSecurity");
    setValue("custom-section-name", "Section");
    customFieldsList.innerHTML = "";
    extraFieldsList.innerHTML = "";
}

function populateForm(entry) {
    setValue("item-id", entry.item_id);
    setValue("share-id", entry.share_id);
    setValue("item-title", entry.item.title);
    setValue("item-note", entry.item.note);

    const [type, payload] = Object.entries(entry.item.content)[0];
    itemTypeSelect.value = type;
    itemTypeSelect.dispatchEvent(new Event("change"));

    customFieldsList.innerHTML = "";
    switch (type) {
        case "Login":
            setValue("login-username", payload.username);
            setValue("login-email", payload.email);
            setValue("login-password", payload.password);
            setValue("login-urls", (payload.urls ?? []).join("\n"));
            break;
        case "CreditCard":
            setValue("cc-cardholder", payload.cardholder_name);
            setValue("cc-type", payload.card_type);
            setValue("cc-number", payload.number);
            setValue("cc-verification", payload.verification_number);
            setValue("cc-expiration", payload.expiration_date);
            setValue("cc-pin", payload.pin);
            break;
        case "Identity":
            setValue("identity-full-name", payload.full_name);
            setValue("identity-email", payload.email);
            setValue("identity-phone", payload.phone_number);
            setValue("identity-organization", payload.organization);
            break;
        case "SshKey":
            setValue("ssh-public-key", payload.public_key);
            setValue("ssh-private-key", payload.private_key);
            break;
        case "Wifi":
            setValue("wifi-ssid", payload.ssid);
            setValue("wifi-password", payload.password);
            setValue("wifi-security", payload.security);
            break;
        case "Custom":
            setValue("custom-section-name", payload.sections[0]?.section_name ?? "Section");
            populateDynamicFields(customFieldsList, payload.sections[0]?.section_fields ?? []);
            break;
        default:
            break;
    }

    populateDynamicFields(extraFieldsList, entry.item.extra_fields);
}

function enterEditMode(entry) {
    editingItemId = entry.item_id;
    populateForm(entry);
    addItemHeading.textContent = "Edit item";
    addItemBtn.textContent = "Save item";
    cancelEditBtn.hidden = false;
    hideStatus();
    addItemHeading.scrollIntoView({ behavior: "smooth", block: "start" });
}

function exitEditMode() {
    editingItemId = null;
    addItemHeading.textContent = "Add item";
    addItemBtn.textContent = "Add item";
    cancelEditBtn.hidden = true;
}

cancelEditBtn.addEventListener("click", () => {
    exitEditMode();
    clearAddItemForm();
});

function openViewDialog(entry) {
    viewItemJson.textContent = JSON.stringify(entry, null, 2);
    viewDialog.showModal();
}

document.getElementById("close-view-item-btn").addEventListener("click", () => viewDialog.close());

function renderItems() {
    itemsTableBody.innerHTML = "";
    itemCountEl.textContent = String(items.length);
    itemsEmptyState.hidden = items.length > 0;

    for (const entry of items) {
        const row = document.createElement("tr");

        const type = Object.keys(entry.item.content)[0];

        row.innerHTML = `
            <td>${entry.item_id}</td>
            <td>${entry.share_id}</td>
            <td>${type}</td>
            <td>${entry.item.title || "(untitled)"}</td>
            <td>${summarize(entry.item)}</td>
        `;

        const actionsCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "row-actions";

        const viewBtn = document.createElement("button");
        viewBtn.type = "button";
        viewBtn.className = "icon-btn";
        viewBtn.textContent = "View";
        viewBtn.addEventListener("click", () => openViewDialog(entry));

        const editBtn = document.createElement("button");
        editBtn.type = "button";
        editBtn.className = "icon-btn";
        editBtn.textContent = "Edit";
        editBtn.addEventListener("click", () => enterEditMode(entry));

        const deleteBtn = document.createElement("button");
        deleteBtn.type = "button";
        deleteBtn.className = "remove-field-btn";
        deleteBtn.textContent = "×";
        deleteBtn.addEventListener("click", () => {
            items = items.filter((i) => i.item_id !== entry.item_id);
            if (editingItemId === entry.item_id) {
                exitEditMode();
                clearAddItemForm();
            }
            renderItems();
        });

        actions.append(viewBtn, editBtn, deleteBtn);
        actionsCell.appendChild(actions);
        row.appendChild(actionsCell);

        itemsTableBody.appendChild(row);
    }
}

addItemBtn.addEventListener("click", () => {
    hideStatus();
    const type = itemTypeSelect.value;

    try {
        const content = buildContent(type);
        const providedId = value("item-id").trim();
        const itemId = providedId || editingItemId || nextItemId();

        if (!editingItemId && items.some((entry) => entry.item_id === itemId)) {
            throw new Error(`Item ID "${itemId}" already exists`);
        }

        const existingUuid = editingItemId
            ? items.find((entry) => entry.item_id === editingItemId)?.item.item_uuid
            : undefined;

        const built = {
            item_id: itemId,
            share_id: value("share-id") || "share1",
            item: {
                title: value("item-title"),
                note: value("item-note"),
                item_uuid: existingUuid ?? crypto.randomUUID(),
                content,
                extra_fields: readDynamicFields(extraFieldsList),
                platform_specific: undefined,
                custom_icon: undefined,
            },
        };

        if (editingItemId) {
            const index = items.findIndex((entry) => entry.item_id === editingItemId);
            if (index !== -1) {
                items[index] = built;
            }
            exitEditMode();
            clearAddItemForm();
        } else {
            items.push(built);
            clearAddItemForm();
        }

        renderItems();
    } catch (error) {
        showStatus(`Could not save item: ${error.message || error}`, true);
    }
});

document.getElementById("clear-items-btn").addEventListener("click", () => {
    items = [];
    resultsPanel.hidden = true;
    hideStatus();
    exitEditMode();
    clearAddItemForm();
    renderItems();
});

document.getElementById("check-duplicates-btn").addEventListener("click", () => {
    hideStatus();
    try {
        const groups = find_duplicate_items_wasm(items);
        renderResults(groups);
    } catch (error) {
        showStatus(`Duplicate detection failed: ${error.message || error}`, true);
    }
});

function renderResults(groups) {
    resultsPanel.hidden = false;
    resultsContent.innerHTML = "";

    if (groups.length === 0) {
        resultsContent.innerHTML = "<p class=\"empty-state\">No duplicates found.</p>";
        return;
    }

    const itemById = new Map(items.map((entry) => [entry.item_id, entry]));

    groups.forEach((group, index) => {
        const card = document.createElement("div");
        card.className = "result-group";

        const heading = document.createElement("h3");
        heading.textContent = `Group ${index + 1} (${group.items.length} items)`;
        card.appendChild(heading);

        const list = document.createElement("ul");
        for (const ref of group.items) {
            const entry = itemById.get(ref.item_id);
            const li = document.createElement("li");
            li.textContent = entry
                ? `${ref.item_id} (${ref.share_id}) - ${entry.item.title || "(untitled)"}`
                : `${ref.item_id} (${ref.share_id})`;
            list.appendChild(li);
        }
        card.appendChild(list);

        resultsContent.appendChild(card);
    });
}

document.getElementById("export-json-btn").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "duplicate-detection-items.json";
    link.click();
    URL.revokeObjectURL(url);
});

document.getElementById("import-json-btn").addEventListener("click", () => {
    importJsonInput.click();
});

importJsonInput.addEventListener("change", async () => {
    const file = importJsonInput.files[0];
    if (!file) {
        return;
    }

    try {
        const text = await file.text();
        const parsed = JSON.parse(text);

        if (!Array.isArray(parsed)) {
            throw new Error("Expected a JSON array of items");
        }

        items = parsed;
        nextId =
            1 +
            items.reduce((max, entry) => {
                const match = /^item-(\d+)$/.exec(entry.item_id || "");
                return match ? Math.max(max, Number(match[1])) : max;
            }, 0);

        resultsPanel.hidden = true;
        hideStatus();
        exitEditMode();
        clearAddItemForm();
        renderItems();
    } catch (error) {
        showStatus(`Could not import JSON: ${error.message || error}`, true);
    } finally {
        importJsonInput.value = "";
    }
});

async function main() {
    try {
        await init();
    } catch (error) {
        showStatus(`Failed to load WASM module: ${error.message || error}`, true);
        return;
    }

    renderItems();
}

main();
