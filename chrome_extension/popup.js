document.getElementById('autofillBtn').addEventListener('click', async () => {
  const site = document.getElementById('site').value.trim();
  const status = document.getElementById('status');
  if (!site) {
    status.textContent = 'Please enter a site/app name.';
    return;
  }
  status.textContent = 'Requesting credentials...';
  try {
    const response = await fetch('http://localhost:5005/get_credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ site })
    });
    if (!response.ok) {
      const err = await response.json();
      status.textContent = err.error || 'Error retrieving credentials.';
      return;
    }
    const data = await response.json();
    status.textContent = 'Filling credentials...';
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.scripting.executeScript({
        target: {tabId: tabs[0].id},
        func: (username, password) => {
          // Try to fill common login forms
          const userFields = ['input[type=email]', 'input[type=text][name*=user]', 'input[type=text][name*=email]', 'input[type=text][id*=user]', 'input[type=text][id*=email]'];
          const passFields = ['input[type=password]'];
          let userInput = null, passInput = null;
          for (const sel of userFields) {
            userInput = document.querySelector(sel);
            if (userInput) break;
          }
          for (const sel of passFields) {
            passInput = document.querySelector(sel);
            if (passInput) break;
          }
          if (userInput) userInput.value = username;
          if (passInput) passInput.value = password;
        },
        args: [data.username, data.password]
      });
    });
    status.textContent = 'Autofill complete!';
  } catch (e) {
    status.textContent = 'Error: ' + e.message;
  }
}); 