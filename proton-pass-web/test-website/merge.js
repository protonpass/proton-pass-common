import init, { plan_group_merge_wasm } from "./pkg/duplicate/proton_pass_web.js";

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

function buildContent(type) {
    switch (type) {
        case "Login":
            return {
                Login: {
                    email: value("login-email"),
                    username: value("login-username"),
                    password: value("login-password"),
                    urls: linesOf("login-urls"),
                    totp_uri: value("login-totp"),
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
                    expiration_date: "",
                    pin: "",
                },
            };
        case "Identity":
            return {
                Identity: {
                    full_name: value("identity-full-name"),
                    email: value("identity-email"),
                    phone_number: value("identity-phone"),
                    first_name: "",
                    middle_name: "",
                    last_name: "",
                    birthdate: value("identity-birthdate"),
                    gender: "",
                    extra_personal_details: [],
                    organization: "",
                    street_address: value("identity-address"),
                    zip_or_postal_code: "",
                    city: "",
                    state_or_province: "",
                    country_or_region: "",
                    floor: "",
                    county: "",
                    extra_address_details: [],
                    social_security_number: value("identity-ssn"),
                    passport_number: value("identity-passport"),
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
                    company: value("identity-company"),
                    job_title: value("identity-job-title"),
                    personal_website: "",
                    work_phone_number: "",
                    work_email: "",
                    extra_work_details: [],
                    extra_sections: [],
                },
            };
        case "SshKey":
            return {
                SshKey: {
                    private_key: "",
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
            )}${payload.totp_uri ? " / 2FA" : ""}`;
        case "CreditCard":
            return payload.number ? `card ending ${payload.number.slice(-4)}` : "(no number)";
        case "SshKey":
            return payload.public_key ? "has public key" : "(empty)";
        case "Wifi":
            return `${payload.ssid || "(no ssid)"} / ${payload.security}`;
        case "Identity":
            return `${payload.full_name || payload.email || "(no identity)"}${payload.company ? ` / ${payload.company}` : ""}`;
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
        "login-totp",
        "login-urls",
        "cc-cardholder",
        "cc-number",
        "cc-verification",
        "identity-full-name",
        "identity-email",
        "identity-phone",
        "identity-birthdate",
        "identity-ssn",
        "identity-passport",
        "identity-company",
        "identity-job-title",
        "identity-address",
        "ssh-public-key",
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
            setValue("login-totp", payload.totp_uri);
            setValue("login-urls", (payload.urls ?? []).join("\n"));
            break;
        case "CreditCard":
            setValue("cc-cardholder", payload.cardholder_name);
            setValue("cc-type", payload.card_type);
            setValue("cc-number", payload.number);
            setValue("cc-verification", payload.verification_number);
            break;
        case "Identity":
            setValue("identity-full-name", payload.full_name);
            setValue("identity-email", payload.email);
            setValue("identity-phone", payload.phone_number);
            setValue("identity-birthdate", payload.birthdate);
            setValue("identity-ssn", payload.social_security_number);
            setValue("identity-passport", payload.passport_number);
            setValue("identity-company", payload.company);
            setValue("identity-job-title", payload.job_title);
            setValue("identity-address", payload.street_address);
            break;
        case "SshKey":
            setValue("ssh-public-key", payload.public_key);
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

function openViewDialog(contents) {
    viewItemJson.textContent = JSON.stringify(contents, null, 2);
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

        const primaryCell = document.createElement("td");
        const primaryRadio = document.createElement("input");
        primaryRadio.type = "radio";
        primaryRadio.name = "merge-primary";
        primaryRadio.className = "merge-select";
        primaryRadio.checked = selectedPrimaryId === entry.item_id;
        primaryRadio.addEventListener("change", () => {
            selectedPrimaryId = entry.item_id;
            hideStatus();
        });
        primaryCell.appendChild(primaryRadio);

        const secondaryCell = document.createElement("td");
        const secondaryCheck = document.createElement("input");
        secondaryCheck.type = "checkbox";
        secondaryCheck.className = "merge-select";
        secondaryCheck.checked = selectedSecondaryIds.includes(entry.item_id);
        secondaryCheck.addEventListener("change", () => {
            if (secondaryCheck.checked) {
                if (!selectedSecondaryIds.includes(entry.item_id)) {
                    selectedSecondaryIds.push(entry.item_id);
                }
            } else {
                selectedSecondaryIds = selectedSecondaryIds.filter((id) => id !== entry.item_id);
            }
            hideStatus();
        });
        secondaryCell.appendChild(secondaryCheck);

        row.append(primaryCell, secondaryCell);

        const cells = [entry.item_id, entry.share_id, type, entry.item.title || "(untitled)", summarize(entry.item)];
        for (const cellValue of cells) {
            const cell = document.createElement("td");
            cell.textContent = cellValue;
            row.appendChild(cell);
        }

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
            if (selectedPrimaryId === entry.item_id) {
                selectedPrimaryId = null;
            }
            selectedSecondaryIds = selectedSecondaryIds.filter((id) => id !== entry.item_id);
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

let selectedPrimaryId = null;
let selectedSecondaryIds = [];

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
    selectedPrimaryId = null;
    selectedSecondaryIds = [];
    resultsPanel.hidden = true;
    hideStatus();
    exitEditMode();
    clearAddItemForm();
    renderItems();
});

document.getElementById("plan-merge-btn").addEventListener("click", () => {
    hideStatus();

    const primary = items.find((entry) => entry.item_id === selectedPrimaryId);
    const secondaries = items.filter((entry) => selectedSecondaryIds.includes(entry.item_id));

    if (!primary) {
        showStatus("Select a primary item first.", true);
        return;
    }
    if (selectedSecondaryIds.includes(selectedPrimaryId)) {
        showStatus("The primary item cannot also be a secondary.", true);
        return;
    }
    if (secondaries.length === 0) {
        showStatus("Select at least one secondary item to merge.", true);
        return;
    }

    try {
        const group = plan_group_merge_wasm({ primary, secondaries });
        renderResults(group, { primary, secondaries });
    } catch (error) {
        showStatus(`Merge planning failed: ${error.message || error}`, true);
    }
});

const DIFF_MARKER_LABELS = {
    "+": "added to the merged item",
    "-": "secondary value kept out of the field (preserved as a custom field)",
    " ": "unchanged",
};

function displayValue(value, max = 72) {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    return text.length > max ? `${text.slice(0, max)}…` : text;
}

function diffLine(marker, text) {
    const line = document.createElement("div");
    line.className = `diff-line diff-${marker === "+" ? "add" : marker === "-" ? "del" : "ctx"}`;
    const markerSpan = document.createElement("span");
    markerSpan.className = "diff-marker";
    markerSpan.textContent = marker;
    line.append(markerSpan, document.createTextNode(text));
    return line;
}

function extraFieldType(content) {
    return Object.keys(content)[0];
}

function extraFieldValue(content) {
    return Object.values(content)[0];
}

function sameField(a, b) {
    return a.name === b.name && JSON.stringify(a.content) === JSON.stringify(b.content);
}

function renderStepDiff(before, secondary, plan) {
    const diff = document.createElement("div");
    diff.className = "diff";
    const merged = plan.merged_item;
    const lines = [];

    // Title: kept from the primary; the secondary's differing title is the "rejected" line.
    lines.push([" ", `title: ${displayValue(before.title)}`]);
    if (secondary.item.title !== before.title) {
        lines.push(["-", `title (from ${secondary.item_id}): ${displayValue(secondary.item.title)}`]);
    }

    const diffContent = (label, beforeValue, secondaryValue, mergedValue) => {
        if (mergedValue !== beforeValue) {
            lines.push(["+", `${label}: ${displayValue(mergedValue)}`]);
        } else {
            lines.push([" ", `${label}: ${displayValue(beforeValue)}`]);
            if (secondaryValue !== beforeValue && secondaryValue !== "" && secondaryValue !== null) {
                lines.push(["-", `${label} (from ${secondary.item_id}): ${displayValue(secondaryValue)}`]);
            }
        }
    };
    const diffSectionField = (sectionName, field, isNew) => {
        const type = extraFieldType(field.content);
        lines.push([
            isNew ? "+" : " ",
            `section "${sectionName}" field "${field.name}" (${type}): ${displayValue(extraFieldValue(field.content))}`,
        ]);
    };
    const diffSections = (beforeSections, mergedSections) => {
        for (const section of mergedSections) {
            const beforeSection = beforeSections.find((s) => s.section_name === section.section_name);
            if (!beforeSection) {
                for (const field of section.section_fields) {
                    diffSectionField(section.section_name, field, true);
                }
                continue;
            }
            for (const field of section.section_fields) {
                const isNew = !beforeSection.section_fields.some((f) => sameField(f, field));
                diffSectionField(section.section_name, field, isNew);
            }
        }
    };

    diffContent("note", before.note, secondary.item.note, merged.note);

    const type = Object.keys(before.content)[0];
    if (type === "Login") {
        const beforeLogin = before.content.Login;
        const secondaryLogin = secondary.item.content.Login;
        const mergedLogin = merged.content.Login;

        for (const key of ["email", "username", "password", "totp_uri"]) {
            diffContent(key, beforeLogin[key], secondaryLogin[key], mergedLogin[key]);
        }

        const union = (label, beforeList, mergedList, keyOf) => {
            for (const item of mergedList) {
                const isNew = !beforeList.some((existing) => keyOf(existing) === keyOf(item));
                lines.push([isNew ? "+" : " ", `${label}: ${displayValue(keyOf(item))}`]);
            }
        };
        union("url", beforeLogin.urls, mergedLogin.urls, (u) => u);
        union("autofill url", beforeLogin.autofill_urls, mergedLogin.autofill_urls, (u) => u.url);
        union("passkey", beforeLogin.passkeys, mergedLogin.passkeys, (p) => p.key_id);
    } else if (type === "CreditCard") {
        const beforeCard = before.content.CreditCard;
        const secondaryCard = secondary.item.content.CreditCard;
        const mergedCard = merged.content.CreditCard;

        for (const key of ["cardholder_name", "number", "verification_number", "expiration_date", "pin"]) {
            diffContent(key, beforeCard[key], secondaryCard[key], mergedCard[key]);
        }
        diffContent("card_type", beforeCard.card_type, secondaryCard.card_type, mergedCard.card_type);
    } else if (type === "Identity") {
        const beforeIdentity = before.content.Identity;
        const secondaryIdentity = secondary.item.content.Identity;
        const mergedIdentity = merged.content.Identity;

        for (const key of [
            "full_name",
            "email",
            "phone_number",
            "first_name",
            "middle_name",
            "last_name",
            "birthdate",
            "gender",
            "social_security_number",
            "passport_number",
            "license_number",
            "organization",
            "street_address",
            "zip_or_postal_code",
            "city",
            "state_or_province",
            "country_or_region",
            "floor",
            "county",
            "website",
            "x_handle",
            "second_phone_number",
            "linkedin",
            "reddit",
            "facebook",
            "yahoo",
            "instagram",
            "company",
            "job_title",
            "personal_website",
            "work_phone_number",
            "work_email",
        ]) {
            diffContent(key, beforeIdentity[key], secondaryIdentity[key], mergedIdentity[key]);
        }

        const unionDetails = (label, beforeList, secondaryList, mergedList) => {
            for (const field of mergedList) {
                const isNew = !beforeList.some((existing) => sameField(existing, field));
                lines.push([
                    isNew ? "+" : " ",
                    `${label} field "${field.name}": ${displayValue(extraFieldValue(field.content))}`,
                ]);
            }
        };
        unionDetails("personal detail", beforeIdentity.extra_personal_details, secondaryIdentity.extra_personal_details, mergedIdentity.extra_personal_details);
        unionDetails("address detail", beforeIdentity.extra_address_details, secondaryIdentity.extra_address_details, mergedIdentity.extra_address_details);
        unionDetails("contact detail", beforeIdentity.extra_contact_details, secondaryIdentity.extra_contact_details, mergedIdentity.extra_contact_details);
        unionDetails("work detail", beforeIdentity.extra_work_details, secondaryIdentity.extra_work_details, mergedIdentity.extra_work_details);
        diffSections(beforeIdentity.extra_sections, mergedIdentity.extra_sections);
    } else if (type === "Wifi") {
        const beforeWifi = before.content.Wifi;
        const secondaryWifi = secondary.item.content.Wifi;
        const mergedWifi = merged.content.Wifi;

        diffContent("ssid", beforeWifi.ssid, secondaryWifi.ssid, mergedWifi.ssid);
        diffContent("password", beforeWifi.password, secondaryWifi.password, mergedWifi.password);
        diffContent("security", beforeWifi.security, secondaryWifi.security, mergedWifi.security);
        diffSections(beforeWifi.sections, mergedWifi.sections);
    } else if (type === "SshKey") {
        const beforeKey = before.content.SshKey;
        const secondaryKey = secondary.item.content.SshKey;
        const mergedKey = merged.content.SshKey;

        diffContent("public_key", beforeKey.public_key, secondaryKey.public_key, mergedKey.public_key);
        diffContent("private_key", beforeKey.private_key, secondaryKey.private_key, mergedKey.private_key);
        diffSections(beforeKey.sections, mergedKey.sections);
    } else if (type === "Custom") {
        diffSections(before.content.Custom.sections, merged.content.Custom.sections);
    }

    // Extra fields: new ones (union additions and conflict-preserving fields) are + lines.
    for (const field of merged.extra_fields) {
        const isNew = !before.extra_fields.some((existing) => sameField(existing, field));
        lines.push([
            isNew ? "+" : " ",
            `field "${field.name}" (${extraFieldType(field.content)}): ${displayValue(extraFieldValue(field.content))}`,
        ]);
    }

    // Platform-specific data (Android allowed apps).
    const beforeApps = before.platform_specific?.android?.allowed_apps ?? [];
    const mergedApps = merged.platform_specific?.android?.allowed_apps ?? [];
    for (const app of mergedApps) {
        const isNew = !beforeApps.some((existing) => existing.package_name === app.package_name);
        lines.push([isNew ? "+" : " ", `allowed app: ${displayValue(app.package_name)}`]);
    }

    if (merged.custom_icon && !before.custom_icon) {
        lines.push(["+", "custom icon"]);
    }

    for (const [marker, text] of lines) {
        diff.appendChild(diffLine(marker, text));
    }
    return diff;
}

function renderResults(group, { primary, secondaries }) {
    resultsPanel.hidden = false;
    resultsContent.innerHTML = "";

    const legend = document.createElement("p");
    legend.className = "diff-legend";
    for (const [marker, label] of Object.entries(DIFF_MARKER_LABELS)) {
        const entry = document.createElement("span");
        entry.className = "diff-legend-entry";
        const markerSpan = document.createElement("strong");
        markerSpan.textContent = marker;
        entry.append(markerSpan, ` ${label}`);
        legend.appendChild(entry);
    }
    resultsContent.appendChild(legend);

    let before = primary.item;

    for (const [index, plan] of group.secondary_plans.entries()) {
        const card = document.createElement("div");
        card.className = "result-group";

        const heading = document.createElement("h3");
        heading.textContent = `Step ${index + 1}: merge ${plan.secondary_id} into ${
            index === 0 ? plan.primary_id : `${plan.primary_id} (updated)`
        }`;
        card.appendChild(heading);

        card.appendChild(renderStepDiff(before, secondaries[index], plan));
        resultsContent.appendChild(card);

        before = plan.merged_item;
    }

    const card = document.createElement("div");
    card.className = "result-group";

    const heading = document.createElement("h3");
    heading.textContent = "Final merged item (primary item would be updated, secondaries moved to trash)";
    card.appendChild(heading);

    const ids = document.createElement("p");
    ids.textContent = `Primary: ${primary.item_id} - trashed: ${secondaries.map((s) => s.item_id).join(", ")}`;
    card.appendChild(ids);

    const mergedBtn = document.createElement("button");
    mergedBtn.type = "button";
    mergedBtn.className = "secondary-btn";
    mergedBtn.style.marginBottom = "10px";
    mergedBtn.textContent = "View merged item JSON";
    const viewSection = document.createElement("div");
    mergedBtn.addEventListener("click", () => openViewDialog({ merged_item: group.merged_item }));
    viewSection.appendChild(mergedBtn);
    card.appendChild(viewSection);


    resultsContent.appendChild(card);
}

document.getElementById("export-json-btn").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "item-merge-items.json";
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

        selectedPrimaryId = null;
        selectedSecondaryIds = [];
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
