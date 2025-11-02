// ============================================================================
// UNIVERSAL CLOUDFLARE TURNSTILE FORM HANDLER - YOUTUBE TUTORIAL VERSION
// ============================================================================
// Generic spam detection system that works with ANY form structure
// Users define field types and data expectations using HTML attributes
//
// REQUIRED ATTRIBUTES:
// - cf-form="unique-id" (on form element)
// - cf-form-purpose="description of form purpose for AI context"
// - cf-turnstile-sitekey="your-site-key"
// - cf-field-type="field-type" (on each input)
// - cf-field-data="expected data description" (on each input)
// ============================================================================

// ========================================
// CONFIGURATION - Modify these as needed
// ========================================
const FORM_CONFIG = {
  // Worker URL - Update this to your deployed worker
  workerUrl: "https://spam-detection-engine.silso.workers.dev/",

  // Form Selectors & Attributes
  formSelector: "form[cf-form]",
  formIdAttribute: "cf-form",
  formPurposeAttribute: "cf-form-purpose",
  siteKeyAttribute: "cf-turnstile-sitekey",
  // Field Type Attributes
  fieldTypeAttribute: "cf-field-type",
  fieldDataAttribute: "cf-field-data",

  // Submit Button Selectors
  submitButtonSelector: '[cf-form-submit="trigger"]',
  submitLabelSelector: '[cf-form-submit="button-label"]',

  // Error Handling Selectors
  errorElementSelector: '[cf-form-submit="error"]',
  errorTextSelector: '[cf-form-submit="error-text"]',

  // Success Element Selector
  successElementSelector: '[cf-form-submit="success"]',

  // CSS Classes
  hideClass: "hide",
  turnstileContainerClass: "cf-turnstile-container",

  // Turnstile Settings
  turnstileTheme: "light",
  turnstileSize: "normal",

  // Loading Text
  loadingText: "sending...",

  // Honeypot Settings
  enableHoneypot: true,
  honeypotFieldNames: [
    "honeypot_website",
    "honeypot_url",
    "honeypot_company_site",
    "honeypot_business_url",
    "bot_trap_website",
    "bot_trap_url",
    "spam_trap_site",
    "spam_trap_link",
  ],

  // Page URL Field
  pageUrlField: {
    enabled: true,
    fieldName: "Page URL",
  },
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
    // Find all forms with cf-form attribute
    const formElements = document.querySelectorAll(FORM_CONFIG.formSelector);
    // console.log(`Universal Form Security: Found ${formElements.length} forms`);

    formElements.forEach((formElement) => {
      this.setupSingleForm(formElement);
    });
  }

  setupSingleForm(formElement) {
    // Extract configuration from custom attributes
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
    };

    // Validate required attributes
    if (!config.siteKey || !config.formPurpose) {
      // console.error("Universal Form Security: Missing required attributes", {
      //   formId: config.formId,
      //   hasSiteKey: !!config.siteKey,
      //   hasFormPurpose: !!config.formPurpose,
      // });
      return;
    }

    // Validate field configurations
    const fieldValidation = this.validateFieldConfiguration(formElement);
    if (!fieldValidation.valid) {
      // console.error(
      //   "Universal Form Security: Invalid field configuration",
      //   fieldValidation.errors
      // );
      return;
    }

    // 🔒 SECURITY: Capture and secure field descriptions before DOM tampering
    const securityData = this.captureAndSecureFieldDescriptions(formElement);
    config[securityData.propertyName] = securityData.securedDescriptions;
    config._securityChecksum = securityData.checksum;

    // 🔒 SECURITY: Also secure the form purpose attribute
    const formPurposeSecurity = this.secureFormPurpose(formElement);
    config[formPurposeSecurity.propertyName] =
      formPurposeSecurity.securedPurpose;
    config._purposeChecksum = formPurposeSecurity.checksum;

    // console.log(`Universal Form Security: Setting up form "${config.formId}"`, {
    //   purpose: config.formPurpose,
    //   fieldsConfigured: fieldValidation.configuredFields,
    //   securityLevel: "ENHANCED",
    //   securedFields: Object.keys(securityData.securedDescriptions).length,
    // });

    // Store form config
    this.forms.push(config);

    // Setup honeypot field
    this.setupHoneypot(config);

    // Setup Page URL field
    this.setupPageUrlField(config);

    // Setup Turnstile and form submission
    this.loadTurnstile(() => this.renderTurnstile(config));
    this.setupFormSubmission(config);
  }

  validateFieldConfiguration(formElement) {
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldTypeAttribute}]`
    );
    const configuredFields = [];
    const errors = [];

    fields.forEach((field) => {
      const fieldType = field.getAttribute(FORM_CONFIG.fieldTypeAttribute);
      const fieldData = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      const fieldName = field.name || field.getAttribute("name");

      if (!fieldType) {
        errors.push(
          `Field "${fieldName}" missing ${FORM_CONFIG.fieldTypeAttribute} attribute`
        );
      }

      if (
        !fieldData &&
        fieldType !== "ignore" &&
        fieldType !== "system-metadata"
      ) {
        errors.push(
          `Field "${fieldName}" missing ${FORM_CONFIG.fieldDataAttribute} attribute`
        );
      }

      if (!fieldName) {
        errors.push(`Field with type "${fieldType}" missing name attribute`);
      }

      configuredFields.push({
        name: fieldName,
        type: fieldType,
        data: fieldData,
      });
    });

    return {
      valid: errors.length === 0,
      errors: errors,
      configuredFields: configuredFields,
    };
  }

  // 🔒 SECURITY: Phase 1 & 2 - Capture and secure field descriptions
  captureAndSecureFieldDescriptions(formElement) {
    const securedDescriptions = {};
    const originalDescriptions = {};
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldDataAttribute}]`
    );

    // console.log(
    //   `🔒 Security: Capturing field descriptions from ${fields.length} fields`
    // );

    // Phase 1: Capture original field descriptions
    fields.forEach((field) => {
      const fieldName = field.name || field.getAttribute("name");
      const fieldDescription = field.getAttribute(
        FORM_CONFIG.fieldDataAttribute
      );

      if (fieldName && fieldDescription) {
        // Store the original description
        securedDescriptions[fieldName] = fieldDescription;
        originalDescriptions[fieldName] = fieldDescription;

        // console.log(
        //   `🔒 Security: Captured description for "${fieldName}": "${fieldDescription.substring(
        //     0,
        //     50
        //   )}..."`
        // );
      }
    });

    // Phase 1: Remove original attributes to prevent tampering
    fields.forEach((field) => {
      field.removeAttribute(FORM_CONFIG.fieldDataAttribute);
    });

    // Phase 2: Add decoy attributes as honeypots for tampering detection
    fields.forEach((field) => {
      const decoyValue =
        "TAMPERED_CONTENT_DETECTED_" +
        Math.random().toString(36).substring(2, 8);
      field.setAttribute(FORM_CONFIG.fieldDataAttribute, decoyValue);
    });

    // Phase 2: Generate integrity checksum
    const checksum = this.generateFieldIntegrityChecksum(originalDescriptions);

    // Phase 2: Use obfuscated property name for storage
    const obfuscatedPropertyName = btoa(
      "securedFieldDescriptions_" + Date.now()
    )
      .replace(/[^a-zA-Z0-9]/g, "")
      .substring(0, 16);

    // console.log(`🔒 Security: Field descriptions secured successfully`);
    // console.log(
    //   `🔒 Security: - Secured ${
    //     Object.keys(securedDescriptions).length
    //   } field descriptions`
    // );
    // console.log(
    //   `🔒 Security: - Added decoy attributes to ${fields.length} fields`
    // );
    // console.log(
    //   `🔒 Security: - Generated integrity checksum: ${checksum.substring(
    //     0,
    //     8
    //   )}...`
    // );
    // console.log(
    //   `🔒 Security: - Using obfuscated property: ${obfuscatedPropertyName}`
    // );

    return {
      securedDescriptions: securedDescriptions,
      propertyName: obfuscatedPropertyName,
      checksum: checksum,
      timestamp: Date.now(),
    };
  }

  // 🔒 SECURITY: Generate integrity checksum for field descriptions
  generateFieldIntegrityChecksum(descriptions) {
    const dataString = JSON.stringify(
      descriptions,
      Object.keys(descriptions).sort()
    );
    let hash = 0;
    if (dataString.length === 0) return hash.toString();
    for (let i = 0; i < dataString.length; i++) {
      const char = dataString.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(36) + Date.now().toString(36);
  }

  // 🔒 SECURITY: Verify field description integrity
  verifyFieldIntegrity(securedDescriptions, expectedChecksum) {
    const currentChecksum =
      this.generateFieldIntegrityChecksum(securedDescriptions);
    // Compare only the hash portion (before timestamp)
    const currentHash = currentChecksum.split(Date.now().toString(36))[0];
    const expectedHash = expectedChecksum.split(/\d+$/)[0];
    return currentHash === expectedHash;
  }

  // 🔒 SECURITY: Detect tampering attempts via decoy attributes
  detectTamperingAttempt(formElement) {
    const fields = formElement.querySelectorAll(
      `[${FORM_CONFIG.fieldDataAttribute}]`
    );
    const tamperingDetected = [];

    fields.forEach((field) => {
      const currentValue = field.getAttribute(FORM_CONFIG.fieldDataAttribute);
      const fieldName = field.name || field.getAttribute("name");

      // Check if the decoy value has been modified
      if (
        currentValue &&
        !currentValue.startsWith("TAMPERED_CONTENT_DETECTED_")
      ) {
        tamperingDetected.push({
          field: fieldName,
          suspiciousValue: currentValue,
        });
      }
    });

    if (tamperingDetected.length > 0) {
      // console.warn(
      //   `🚨 Security: Tampering detected in ${tamperingDetected.length} fields:`,
      //   tamperingDetected
      // );
    }

    return tamperingDetected;
  }

  // 🔒 SECURITY: Secure form purpose attribute against tampering
  secureFormPurpose(formElement) {
    const originalPurpose = formElement.getAttribute(
      FORM_CONFIG.formPurposeAttribute
    );

    if (!originalPurpose) {
      // console.warn("🔒 Security: No form purpose found to secure");
      return {
        securedPurpose: null,
        propertyName: null,
        checksum: null,
      };
    }

    // console.log(
    //   `🔒 Security: Securing form purpose: "${originalPurpose.substring(
    //     0,
    //     50
    //   )}..."`
    // );

    // Remove original attribute to prevent DOM tampering
    formElement.removeAttribute(FORM_CONFIG.formPurposeAttribute);

    // Add decoy attribute for tampering detection
    const decoyValue =
      "TAMPERED_PURPOSE_DETECTED_" + Math.random().toString(36).substring(2, 8);
    formElement.setAttribute(FORM_CONFIG.formPurposeAttribute, decoyValue);

    // Generate integrity checksum
    const checksum = this.generateFormPurposeChecksum(originalPurpose);

    // Use obfuscated property name for storage
    const obfuscatedPropertyName = btoa("securedFormPurpose_" + Date.now())
      .replace(/[^a-zA-Z0-9]/g, "")
      .substring(0, 14); // Slightly different length to distinguish from field data

    // console.log(`🔒 Security: Form purpose secured successfully`);
    // console.log(
    //   `🔒 Security: - Using obfuscated property: ${obfuscatedPropertyName}`
    // );
    // console.log(
    //   `🔒 Security: - Generated purpose checksum: ${checksum.substring(
    //     0,
    //     8
    //   )}...`
    // );

    return {
      securedPurpose: originalPurpose,
      propertyName: obfuscatedPropertyName,
      checksum: checksum,
      timestamp: Date.now(),
    };
  }

  // 🔒 SECURITY: Generate integrity checksum for form purpose
  generateFormPurposeChecksum(purpose) {
    let hash = 0;
    if (!purpose || purpose.length === 0) return hash.toString();

    for (let i = 0; i < purpose.length; i++) {
      const char = purpose.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(36) + Date.now().toString(36);
  }

  // 🔒 SECURITY: Verify form purpose integrity
  verifyFormPurposeIntegrity(securedPurpose, expectedChecksum) {
    const currentChecksum = this.generateFormPurposeChecksum(securedPurpose);
    // Compare only the hash portion (before timestamp)
    const currentHash = currentChecksum.split(/\d+$/)[0];
    const expectedHash = expectedChecksum.split(/\d+$/)[0];
    return currentHash === expectedHash;
  }

  // 🔒 SECURITY: Detect form purpose tampering
  detectFormPurposeTampering(formElement) {
    const currentValue = formElement.getAttribute(
      FORM_CONFIG.formPurposeAttribute
    );

    if (
      currentValue &&
      !currentValue.startsWith("TAMPERED_PURPOSE_DETECTED_")
    ) {
      // console.warn(
      //   `🚨 Security: Form purpose tampering detected: "${currentValue}"`
      // );
      return {
        detected: true,
        suspiciousValue: currentValue,
      };
    }

    return { detected: false };
  }

  setupHoneypot(config) {
    if (!FORM_CONFIG.enableHoneypot) {
      return;
    }

    // Check if honeypot already exists
    const existingHoneypot = config.formElement.querySelector(
      'input[data-honeypot="true"]'
    );
    if (existingHoneypot) {
      return;
    }

    // Create honeypot field with random name
    const randomFieldName =
      FORM_CONFIG.honeypotFieldNames[
        Math.floor(Math.random() * FORM_CONFIG.honeypotFieldNames.length)
      ];

    const honeypotField = document.createElement("input");
    honeypotField.type = "text";
    honeypotField.name = randomFieldName;
    honeypotField.setAttribute("data-honeypot", "true");
    honeypotField.setAttribute("tabindex", "-1");
    honeypotField.setAttribute("autocomplete", "off");

    // Make it invisible but accessible to screen readers
    honeypotField.style.cssText = `
        position: absolute !important;
        left: -9999px !important;
        top: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        opacity: 0 !important;
        pointer-events: none !important;
      `;

    // Add aria-hidden for screen readers
    honeypotField.setAttribute("aria-hidden", "true");

    // Insert at the beginning of the form
    config.formElement.insertBefore(
      honeypotField,
      config.formElement.firstChild
    );

    // console.log(
    //   `Universal Form Security: Added honeypot field "${randomFieldName}"`
    // );
  }

  setupPageUrlField(config) {
    if (!FORM_CONFIG.pageUrlField.enabled) {
      return;
    }

    // Check if Page URL field already exists
    const existingPageUrlField = config.formElement.querySelector(
      `input[name="${FORM_CONFIG.pageUrlField.fieldName}"]`
    );
    if (existingPageUrlField) {
      // Update existing field
      existingPageUrlField.value = window.location.href;
      return;
    }

    // Create Page URL hidden field
    const pageUrlField = document.createElement("input");
    pageUrlField.type = "hidden";
    pageUrlField.name = FORM_CONFIG.pageUrlField.fieldName;
    pageUrlField.value = window.location.href;
    pageUrlField.setAttribute("data-page-url", "true");
    pageUrlField.setAttribute(
      FORM_CONFIG.fieldTypeAttribute,
      "system-metadata"
    );

    // Insert at the beginning of the form
    config.formElement.insertBefore(
      pageUrlField,
      config.formElement.firstChild
    );
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
    // Create container for Turnstile widget
    let turnstileContainer = config.formElement.querySelector(
      `.${FORM_CONFIG.turnstileContainerClass}`
    );
    if (!turnstileContainer) {
      turnstileContainer = document.createElement("div");
      turnstileContainer.className = FORM_CONFIG.turnstileContainerClass;
      turnstileContainer.style.marginBottom = "20px";

      // Insert before submit button
      if (config.submitButton) {
        config.submitButton.parentNode.insertBefore(
          turnstileContainer,
          config.submitButton
        );
      } else {
        // Fallback: append to form
        config.formElement.appendChild(turnstileContainer);
      }
    }

    // Render Turnstile widget and store the widget ID
    config.turnstileWidgetId = window.turnstile.render(turnstileContainer, {
      sitekey: config.siteKey,
      callback: (token) => {
        config.turnstileToken = token;
        this.enableSubmitButton(config);
        // console.log("Universal Form Security: Turnstile token received");
      },
      "error-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
        this.showError(
          config,
          "Security verification failed. Please try again."
        );
        // console.error("Universal Form Security: Turnstile error");
      },
      "expired-callback": () => {
        config.turnstileToken = null;
        this.disableSubmitButton(config);
        // console.log("Universal Form Security: Turnstile token expired");
      },
      theme: FORM_CONFIG.turnstileTheme,
      size: FORM_CONFIG.turnstileSize,
    });

    // Initially disable submit button
    this.disableSubmitButton(config);
  }

  setupFormSubmission(config) {
    config.formElement.addEventListener("submit", (e) => {
      // Let native validation run first
      if (!config.formElement.checkValidity()) {
        return; // Let browser show validation errors
      }

      // Form is valid, now intercept
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      this.handleFormSubmit(config);
    });

    // Also prevent any other form submission events
    config.formElement.addEventListener(
      "submit",
      (e) => {
        e.preventDefault();
      },
      true
    ); // Use capture phase
  }

  async handleFormSubmit(config) {
    // console.log("Universal Form Security: Form submission started");

    // Clear any previous errors
    this.hideError(config);

    // Validate Turnstile token
    if (!config.turnstileToken) {
      this.showError(config, "Please complete the security verification.");
      return;
    }

    // Set loading state
    this.setSubmitButtonLoading(config, true);

    try {
      // Collect form data with field type information and secured form purpose
      const collectionResult = this.collectFormData(config);
      const formData = collectionResult.formData;
      const securedFormPurpose = collectionResult.securedFormPurpose;

      // Add metadata for spam detection
      formData.metadata = {
        submissionTime: Date.now(),
        pageLoadTime: window.performance.timing.loadEventEnd,
        userAgent: navigator.userAgent,
        referrer: document.referrer,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        formId: config.formId,
        formPurpose: securedFormPurpose, // 🔒 Use secured form purpose
      };

      const payload = {
        turnstileToken: config.turnstileToken,
        formData: formData,
        fieldTypes: formData.fieldTypes, // Include field type information
        formPurpose: securedFormPurpose, // 🔒 Use secured form purpose
      };

      // console.log("Universal Form Security: Sending to worker", {
      //   formId: config.formId,
      //   fieldCount: Object.keys(formData).length - 2, // Exclude metadata and fieldTypes
      //   hasFieldTypes: !!formData.fieldTypes,
      // });

      // Submit to Cloudflare Worker
      const response = await fetch(this.workerUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (result.success) {
        // console.log("Universal Form Security: Form submitted successfully");
        this.handleSuccess(config);
      } else {
        // console.log(
        //   "Universal Form Security: Form submission blocked",
        //   result.error
        // );

        // Reset Turnstile on error to generate new token
        this.resetTurnstileOnError(config);

        this.showError(
          config,
          result.error?.message || "Something went wrong. Please try again."
        );
      }
    } catch (error) {
      // console.error("Universal Form Security: Network error", error);

      // Reset Turnstile on error to generate new token
      this.resetTurnstileOnError(config);

      this.showError(
        config,
        "Network error. Please check your connection and try again."
      );
    } finally {
      this.setSubmitButtonLoading(config, false);
    }
  }

  collectFormData(config) {
    const formData = {};
    const fieldTypes = {};
    const fieldDataDescriptions = {};

    // 🔒 SECURITY: Detect tampering attempts before data collection
    const tamperingAttempts = this.detectTamperingAttempt(config.formElement);
    const formPurposeTampering = this.detectFormPurposeTampering(
      config.formElement
    );

    if (tamperingAttempts.length > 0 || formPurposeTampering.detected) {
      // console.warn(
      //   `🚨 Security: ${tamperingAttempts.length} field tampering attempts detected during form submission`
      // );
      // if (formPurposeTampering.detected) {
      //   console.warn(
      //     `🚨 Security: Form purpose tampering detected: "${formPurposeTampering.suspiciousValue}"`
      //   );
      // }
      // Log but don't block - we have secured data anyway
    }

    const inputs = config.formElement.querySelectorAll(
      "input, textarea, select"
    );

    inputs.forEach((input) => {
      if (input.name && input.type !== "submit") {
        // Collect field value
        if (input.type === "checkbox") {
          formData[input.name] = input.checked;
        } else if (input.type === "radio") {
          if (input.checked) {
            formData[input.name] = input.value;
          }
        } else {
          formData[input.name] = input.value;
        }

        // Collect field type information (still from DOM as it's less critical)
        const fieldType = input.getAttribute(FORM_CONFIG.fieldTypeAttribute);

        if (fieldType) {
          fieldTypes[input.name] = fieldType;
        }

        // 🔒 SECURITY: Use secured field descriptions instead of DOM reading
        const securityPropertyName = Object.keys(config).find(
          (key) =>
            key.match(/^[A-Za-z0-9]{16}$/) &&
            config[key] &&
            typeof config[key] === "object"
        );

        if (securityPropertyName && config[securityPropertyName][input.name]) {
          fieldDataDescriptions[input.name] =
            config[securityPropertyName][input.name];
        }
      }
    });

    // 🔒 SECURITY: Verify field description integrity
    if (config._securityChecksum) {
      const securityPropertyName = Object.keys(config).find(
        (key) =>
          key.match(/^[A-Za-z0-9]{16}$/) &&
          config[key] &&
          typeof config[key] === "object"
      );

      if (securityPropertyName) {
        const integrityValid = this.verifyFieldIntegrity(
          config[securityPropertyName],
          config._securityChecksum
        );

        if (!integrityValid) {
          // console.error("🚨 Security: Field integrity verification failed!");
          // Continue with submission but log the security violation
        } else {
          // console.log("🔒 Security: Field integrity verified successfully");
        }
      }
    }

    // 🔒 SECURITY: Verify form purpose integrity and use secured version
    let securedFormPurpose = config.formPurpose; // Fallback to original

    if (config._purposeChecksum) {
      const purposePropertyName = Object.keys(config).find(
        (key) =>
          key.match(/^[A-Za-z0-9]{14}$/) &&
          config[key] &&
          typeof config[key] === "string"
      );

      if (purposePropertyName) {
        const purposeIntegrityValid = this.verifyFormPurposeIntegrity(
          config[purposePropertyName],
          config._purposeChecksum
        );

        if (!purposeIntegrityValid) {
          // console.error(
          //   "🚨 Security: Form purpose integrity verification failed!"
          // );
          // Continue with submission but log the security violation
        } else {
          // console.log(
          //   "🔒 Security: Form purpose integrity verified successfully"
          // );
          securedFormPurpose = config[purposePropertyName]; // Use secured version
        }
      }
    }

    // Add honeypot detection metadata
    if (FORM_CONFIG.enableHoneypot) {
      const honeypotField = config.formElement.querySelector(
        'input[data-honeypot="true"]'
      );
      if (honeypotField) {
        formData._honeypot_field_name = honeypotField.name;
        formData._honeypot_filled = honeypotField.value !== "";
      }
    }

    // Add security metadata
    formData._security_level = "ENHANCED";
    formData._tampering_attempts =
      tamperingAttempts.length + (formPurposeTampering.detected ? 1 : 0);
    formData._form_purpose_tampering = formPurposeTampering.detected;

    // Add field type information to form data
    formData.fieldTypes = fieldTypes;
    formData.fieldDataDescriptions = fieldDataDescriptions;

    // console.log("Universal Form Security: Collected form data", {
    //   fieldCount: Object.keys(formData).length - 5, // Exclude metadata, fieldTypes, fieldDataDescriptions, security fields
    //   configuredFields: Object.keys(fieldTypes).length,
    //   securedDescriptions: Object.keys(fieldDataDescriptions).length,
    //   hasHoneypot: !!formData._honeypot_field_name,
    //   securityLevel: formData._security_level,
    //   tamperingAttempts: formData._tampering_attempts,
    //   formPurposeSecured: !!securedFormPurpose,
    // });

    return {
      formData: formData,
      securedFormPurpose: securedFormPurpose,
    };
  }

  resetTurnstileOnError(config) {
    if (window.turnstile) {
      try {
        // Reset the Turnstile widget to generate a new token
        if (config.turnstileWidgetId) {
          window.turnstile.reset(config.turnstileWidgetId);
        } else {
          window.turnstile.reset();
        }

        // console.log("Universal Form Security: Turnstile reset successful");
      } catch (error) {
        // console.warn("Universal Form Security: Turnstile reset failed", error);
      }

      // Clear the current token and disable submit button until new token received
      config.turnstileToken = null;
      this.disableSubmitButton(config);

      // Re-render turnstile if it seems stuck
      setTimeout(() => {
        if (!config.turnstileToken) {
          // console.log(
          //   "Universal Form Security: Re-rendering Turnstile after reset"
          // );
          this.renderTurnstile(config);
        }
      }, 1000);
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
    // Use the configured error elements
    if (config.errorElement && config.errorText) {
      // Set the error message
      config.errorText.textContent = message;

      // Remove hide class to show error
      config.errorElement.classList.remove(FORM_CONFIG.hideClass);
    } else {
      // Fallback: alert (not ideal but ensures user sees error)
      // console.error(
      //   "Universal Form Security: No error display configured, using alert"
      // );
      alert(message);
    }
  }

  hideError(config) {
    // Use the configured error elements
    if (config.errorElement) {
      // Add hide class to hide error
      config.errorElement.classList.add(FORM_CONFIG.hideClass);
    }
  }

  handleSuccess(config) {
    // console.log("Universal Form Security: Form submission successful");

    // Hide the form
    config.formElement.style.display = "none";

    // Show success element if it exists
    if (config.successElement) {
      config.successElement.style.display = "block";
      // console.log("Universal Form Security: Success message displayed");
    } else {
      // console.warn(
      //   'Universal Form Security: No success element found with cf-form-submit="success"'
      // );
    }

    // Reset Turnstile for potential reuse
    if (window.turnstile) {
      window.turnstile.reset();
    }
    config.turnstileToken = null;
  }
}

// Initialize when page loads
// console.log("Universal Form Security: Initializing...");
new UniversalFormSecurityHandler();
