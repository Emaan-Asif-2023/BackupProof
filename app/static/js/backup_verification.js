"use strict";

document.addEventListener("DOMContentLoaded", function () {
  const resultBox = document.getElementById("verificationResult");

  if (!resultBox) {
    return;
  }

  const backupId = resultBox.dataset.backupId;
  const csrfToken = resultBox.dataset.csrfToken;

  async function checkBackup(url, method) {
    resultBox.textContent = "Checking backup...";

    try {
      const response = await fetch(url, {
        method: method,
        credentials: "same-origin",
        headers: {
          "X-CSRF-Token": csrfToken,
          "Accept": "application/json"
        }
      });

      const data = await response.json();

      if (!response.ok) {
        resultBox.textContent =
          (data.error && data.error.message)
            ? data.error.message
            : "Verification failed.";
        return;
      }

      resultBox.textContent =
        "Status: " + data.status +
        " | Reason: " + data.reason;

    } catch (error) {
      console.error("Backup verification error:", error);
      resultBox.textContent =
        "Unable to contact the verification service.";
    }
  }

  const verifyBtn = document.getElementById("verifyBtn");

  if (verifyBtn) {
    verifyBtn.addEventListener("click", function () {
      checkBackup(
        "/api/backups/" + encodeURIComponent(backupId) + "/verify",
        "POST"
      );
    });
  }

  const retentionBtn = document.getElementById("retentionBtn");

  if (retentionBtn) {
    retentionBtn.addEventListener("click", function () {
      checkBackup(
        "/api/backups/" + encodeURIComponent(backupId) + "/retention",
        "GET"
      );
    });
  }
});