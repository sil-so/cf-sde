// ============================================================================
// UNIVERSAL CLOUDFLARE TURNSTILE FORM HANDLER
// ============================================================================

const FORM_CONFIG = {
  workerUrl: "https://spam-detection-engine.silso.workers.dev/",
  formSelector: "form[cf-form]",
  formIdAttribute: "cf-form",
  formPurposeAttribute: "cf-form-purpose",
  siteKeyAttribute: "cf-turnstile-sitekey",
  fieldTypeAttribute: "cf-field-type",
  fieldDataAttribute: "cf-field-data",
  submitButtonSelector: '[cf-form-submit="trigger"]',
  submitLabelSelector: '[cf-form-submit="button-label"]',
  errorElementSelector: '[cf-form-submit="error"]',
  errorTextSelector: '[cf-form-submit="error-text"]',
  successElementSelector: '[cf-form-submit="success"]',
  hideClass: "hide",
  turnstileContainerClass: "cf-turnstile-container",
  turnstileTheme: "light",
  turnstileSize: "normal",
  loadingText: "sending...",
  enableHoneypot: true,
  honeypotFieldNames: [
    "honeypot_website",
    "honeypot_url",
    "honeypot_company_site",
    "honeypot_business_url",
    "bot_trap_website",
    "bot_trap_url",
    "spam_trap_site",
    "spam_trap_link"
  ],
  pageUrlField: {
    enabled: true,
    fieldName: "Page URL"
  }
};

class UniversalFormSecurityHandler {
  constructor() {
    this.forms = [];
    this.workerUrl = FORM_CONFIG.workerUrl;
    this.init();
  }

  init() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setupForms());
    } else {
      this.setupForms();
    }
  }

  setupForms() {
    const formElements = document.querySelectorAll(FORM_CONFIG.formSelector);
    formElements.forEach((formElement) => {
      // Prevent double initialization on the same form
      if (formElement.dataset.cfSecured === "true") return;
      this.setupSingleForm(formElement);
    });
  }

  setupSingleForm(formElement) {
    const config = {
      formId: formElement.getAttribute(FORM_CONFIG.formIdAttribute),
      formPurpose: formElement.getAttribute(FORM_CONFIG.formPurposeAttribute),
      siteKey: formElement.getAttribute(FORM_CONFIG.siteKeyAttribute),
      formElement: formElement,
      submitButton: formElement.querySelector(FORM_CONFIG.submitButtonSelector),
      submitLabel: formElement.querySelector(FORM_CONFIG.submitLabelSelector),
      errorElement: formElement.querySelector(FORM_CONFIG.errorElementSelector),
      errorText: formElement.querySelector(FORM_CONFIG.errorTextSelector),
      successElement: document.querySelector(
        FORM_CONFIG.successElementSelector
      ),
      turnstileToken: null,
      turnstileWidgetId: null
    };

    if (!config.siteKey || !config.formPurpose) return;

    const fieldValidation = this.validateFieldConfiguration(formElement);
    if (!fieldValidation.valid) return;

    // Security Setup
    const securityData = this.captureAndSecureFieldDescriptions(formElement);
    config[securityData.propertyName] = securityData.securedDescriptions;
    config._securityChecksum = securityData.checksum;

    const formPurposeSecurity = this.secureFormPurpose(formElement);
    config[formPurposeSecurity.propertyName] =
      formPurposeSecurity.securedPurpose;
    config._purposeChecksum = formPurposeSecurity.checksum;

    // Mark form as initialized
    formElement.dataset.cfSecured = "true";
    this.forms.push(config);

    this.setupHoneypot(config);
    this.setupPageUrlField(config);

    // Initial Load
    this.loadTurnstile(() => this.renderTurnstile(config));

    // Setup Listeners
    this.setupFormSubmission(config);
    this.setupRefreshListener(config); // New: Listen for modal re-opens
  }

  /**
   * New Method: Listens for external requests to refresh the security token.
   * Useful for modals or single-page-app navigations.
   */
  setupRefreshListener(config) {
    config.formElement.addEventListener("cf-security-refresh", () => {
      // 1. Remove existing widget if present
      if (config.turnstileWidgetId && window.turnstile) {
        try {
          window.turnstile.remove(config.turnstileWidgetId);
        } catch (e) {
          /* ignore cleanup errors */
        }
      }

      // 2. Clear token
      config.turnstileToken = null;
      config.turnstileWidgetId = null;
      this.disableSubmitButton(config);

      // 3. Clean container HTML to ensure fresh render
      const container = config.formElement.querySelector(
        `.${FORM_CONFIG.turnstileContainerClass}`
      );
      if (container) container.innerHTML = "";

      // 4. Re-render
      if (window.turnstile) {
        this.renderTurnstile(config);
      } else {
        this.loadTurnstile(() => this.renderTurnstile(config));
      }
    });
  }

  validateFieldConfiguration(formElement) {
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldTypeAttribute}]`
    );
    const errors = [];
    fields.forEach((field) => {
      const fieldType = field.getAttribute(FORM_CONFIG.fieldTypeAttribute);
      const fieldData = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      const fieldName = field.name || field.getAttribute("name");

      if (!fieldType) errors.push(`Field "${fieldName}" missing type`);
      if (
        !fieldData &&
        fieldType !== "ignore" &&
        fieldType !== "system-metadata"
      ) {
        errors.push(`Field "${fieldName}" missing data description`);
      }
      if (!fieldName) errors.push(`Field type "${fieldType}" missing name`);
    });
    return { valid: errors.length === 0, errors: errors };
  }

  captureAndSecureFieldDescriptions(formElement) {
    const securedDescriptions = {};
    const originalDescriptions = {};
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldDataAttribute}]`
    );

    fields.forEach((field) => {
      const fieldName = field.name || field.getAttribute("name");
      const desc = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      if (fieldName && desc) {
        securedDescriptions[fieldName] = desc;
        originalDescriptions[fieldName] = desc;
      }
    });

    fields.forEach((field) => {
      field.removeAttribute(FORM_CONFIG.fieldDataAttribute);
      field.setAttribute(
        FORM_CONFIG.fieldDataAttribute,
        "TAMPERED_CONTENT_DETECTED_" + Math.random().toString(36).substring(7)
      );
    });

    const checksum = this.generateFieldIntegrityChecksum(originalDescriptions);
    const propName = btoa("secured_" + Date.now())
      .replace(/[^a-zA-Z0-9]/g, "")
      .substring(0, 16);

    return {
      securedDescriptions: securedDescriptions,
      propertyName: propName,
      checksum: checksum
    };
  }

  generateFieldIntegrityChecksum(descriptions) {
    const str = JSON.stringify(descriptions, Object.keys(descriptions).sort());
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36) + Date.now().toString(36);
  }

  verifyFieldIntegrity(securedDescriptions, expectedChecksum) {
    const current = this.generateFieldIntegrityChecksum(securedDescriptions);
    return (
      current.split(Date.now().toString(36))[0] ===
      expectedChecksum.split(/\d+$/)[0]
    );
  }

  detectTamperingAttempt(formElement) {
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldDataAttribute}]`
    );
    const attempts = [];
    fields.forEach((field) => {
      const val = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      if (val && !val.startsWith("TAMPERED_CONTENT_DETECTED_")) {
        attempts.push({ field: field.name, value: val });
      }
    });
    return attempts;
  }

  secureFormPurpose(formElement) {
    const original = formElement.getAttribute(FORM_CONFIG.formPurposeAttribute);
    if (!original)
      return { securedPurpose: null, propertyName: null, checksum: null };

    formElement.removeAttribute(FORM_CONFIG.formPurposeAttribute);
    formElement.setAttribute(
      FORM_CONFIG.formPurposeAttribute,
      "TAMPERED_PURPOSE_" + Math.random().toString(36).substring(7)
    );

    const checksum = this.generateFormPurposeChecksum(original);
    const propName = btoa("purpose_" + Date.now())
      .replace(/[^a-zA-Z0-9]/g, "")
      .substring(0, 14);

    return {
      securedPurpose: original,
      propertyName: propName,
      checksum: checksum
    };
  }

  generateFormPurposeChecksum(purpose) {
    let hash = 0;
    if (!purpose) return hash.toString();
    for (let i = 0; i < purpose.length; i++) {
      hash = (hash << 5) - hash + purpose.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36) + Date.now().toString(36);
  }

  detectFormPurposeTampering(formElement) {
    const val = formElement.getAttribute(FORM_CONFIG.formPurposeAttribute);
    return {
      detected: val && !val.startsWith("TAMPERED_PURPOSE_"),
      suspiciousValue: val
    };
  }

  setupHoneypot(config) {
    if (
      !FORM_CONFIG.enableHoneypot ||
      config.formElement.querySelector('input[data-honeypot="true"]')
    )
      return;

    const name =
      FORM_CONFIG.honeypotFieldNames[
        Math.floor(Math.random() * FORM_CONFIG.honeypotFieldNames.length)
      ];
    const input = document.createElement("input");
    input.type = "text";
    input.name = name;
    input.setAttribute("data-honeypot", "true");
    input.tabIndex = -1;
    input.autocomplete = "off";
    input.setAttribute("aria-hidden", "true");
    input.style.cssText =
      "position:absolute!important;left:-9999px!important;opacity:0!important;pointer-events:none!important;";

    config.formElement.insertBefore(input, config.formElement.firstChild);
  }

  setupPageUrlField(config) {
    if (!FORM_CONFIG.pageUrlField.enabled) return;
    const name = FORM_CONFIG.pageUrlField.fieldName;
    if (config.formElement.querySelector(`input[name="${name}"]`)) return;

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = window.location.href;
    input.setAttribute("data-page-url", "true");
    input.setAttribute(FORM_CONFIG.fieldTypeAttribute, "system-metadata");
    config.formElement.insertBefore(input, config.formElement.firstChild);
  }

  loadTurnstile(callback) {
    if (!window.turnstile) {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
      script.async = true;
      script.defer = true;
      script.onload = callback;
      document.head.appendChild(script);
    } else {
      callback();
    }
  }

  renderTurnstile(config) {
    let container = config.formElement.querySelector(
      `.${FORM_CONFIG.turnstileContainerClass}`
    );
    if (!container) {
      container = document.createElement("div");
      container.className = FORM_CONFIG.turnstileContainerClass;
      container.style.marginBottom = "20px";
      if (config.submitButton) {
        config.submitButton.parentNode.insertBefore(
          container,
          config.submitButton
        );
      } else {
        config.formElement.appendChild(container);
      }
    }

    config.turnstileWidgetId = window.turnstile.render(container, {
      sitekey: config.siteKey,
      callback: (token) => {
        config.turnstileToken = token;
        this.enableSubmitButton(config);
      },
      "error-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
        this.showError(
          config,
          "Security verification failed. Please try again."
        );
      },
      "expired-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
      },
      theme: FORM_CONFIG.turnstileTheme,
      size: FORM_CONFIG.turnstileSize
    });

    this.disableSubmitButton(config);
  }

  setupFormSubmission(config) {
    config.formElement.addEventListener(
      "submit",
      (e) => {
        if (!config.formElement.checkValidity()) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        this.handleFormSubmit(config);
      },
      true
    );
  }

  async handleFormSubmit(config) {
    this.hideError(config);

    if (!config.turnstileToken) {
      this.showError(config, "Please complete the security verification.");
      return;
    }

    this.setSubmitButtonLoading(config, true);

    try {
      const { formData, securedFormPurpose } = this.collectFormData(config);

      formData.metadata = {
        submissionTime: Date.now(),
        userAgent: navigator.userAgent,
        referrer: document.referrer,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        formId: config.formId,
        formPurpose: securedFormPurpose
      };

      const payload = {
        turnstileToken: config.turnstileToken,
        formData: formData,
        fieldTypes: formData.fieldTypes,
        formPurpose: securedFormPurpose
      };

      const response = await fetch(this.workerUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const result = await response.json();

      if (result.success) {
        this.handleSuccess(config);
      } else {
        this.resetTurnstileOnError(config);
        this.showError(
          config,
          result.error?.message || "Something went wrong."
        );
      }
    } catch (error) {
      this.resetTurnstileOnError(config);
      this.showError(config, "Network error. Please try again.");
    } finally {
      this.setSubmitButtonLoading(config, false);
    }
  }

  collectFormData(config) {
    const formData = {};
    const fieldTypes = {};
    const fieldDataDescriptions = {};

    const tamperingAttempts = this.detectTamperingAttempt(config.formElement);
    const purposeTamper = this.detectFormPurposeTampering(config.formElement);

    const inputs = config.formElement.querySelectorAll(
      "input, textarea, select"
    );

    // Find security key
    const secKey = Object.keys(config).find((k) =>
      k.match(/^[A-Za-z0-9]{16}$/)
    );

    inputs.forEach((input) => {
      if (!input.name || input.type === "submit") return;

      if (input.type === "checkbox") formData[input.name] = input.checked;
      else if (input.type === "radio") {
        if (input.checked) formData[input.name] = input.value;
      } else formData[input.name] = input.value;

      const type = input.getAttribute(FORM_CONFIG.fieldTypeAttribute);
      if (type) fieldTypes[input.name] = type;

      if (secKey && config[secKey] && config[secKey][input.name]) {
        fieldDataDescriptions[input.name] = config[secKey][input.name];
      }
    });

    let securedPurpose = config.formPurpose;
    const purposeKey = Object.keys(config).find((k) =>
      k.match(/^[A-Za-z0-9]{14}$/)
    );
    if (purposeKey && config[purposeKey]) securedPurpose = config[purposeKey];

    if (FORM_CONFIG.enableHoneypot) {
      const honey = config.formElement.querySelector(
        'input[data-honeypot="true"]'
      );
      if (honey) {
        formData._honeypot_field_name = honey.name;
        formData._honeypot_filled = honey.value !== "";
      }
    }

    formData._security_level = "ENHANCED";
    formData._tampering_attempts =
      tamperingAttempts.length + (purposeTamper.detected ? 1 : 0);
    formData.fieldTypes = fieldTypes;
    formData.fieldDataDescriptions = fieldDataDescriptions;

    return { formData, securedFormPurpose: securedPurpose };
  }

  resetTurnstileOnError(config) {
    if (window.turnstile && config.turnstileWidgetId) {
      window.turnstile.reset(config.turnstileWidgetId);
      config.turnstileToken = null;
      this.disableSubmitButton(config);
    }
  }

  enableSubmitButton(config) {
    if (config.submitButton) {
      config.submitButton.disabled = false;
      config.submitButton.style.opacity = "1";
    }
  }

  disableSubmitButton(config) {
    if (config.submitButton) {
      config.submitButton.disabled = true;
      config.submitButton.style.opacity = "0.6";
    }
  }

  setSubmitButtonLoading(config, loading) {
    if (!config.submitButton) return;
    if (loading) {
      config.submitButton.disabled = true;
      if (config.submitLabel) {
        config.originalButtonText = config.submitLabel.innerHTML;
        config.submitLabel.innerHTML = FORM_CONFIG.loadingText;
      }
    } else {
      config.submitButton.disabled = false;
      if (config.submitLabel && config.originalButtonText) {
        config.submitLabel.innerHTML = config.originalButtonText;
      }
    }
  }

  showError(config, message) {
    if (config.errorElement && config.errorText) {
      config.errorText.textContent = message;
      config.errorElement.classList.remove(FORM_CONFIG.hideClass);
    } else {
      alert(message);
    }
  }

  hideError(config) {
    if (config.errorElement)
      config.errorElement.classList.add(FORM_CONFIG.hideClass);
  }

  handleSuccess(config) {
    config.formElement.style.display = "none";
    if (config.successElement) config.successElement.style.display = "block";
    if (window.turnstile) window.turnstile.reset();
    config.turnstileToken = null;
  }
}

new UniversalFormSecurityHandler();
