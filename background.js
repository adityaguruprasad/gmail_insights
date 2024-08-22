const CLIENT_ID = 'YOUR_GMAIL_CLIENT_ID.apps.googleusercontent.com';
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("fetchInsights", { periodInMinutes: 60 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "fetchInsights") {
    fetchAndProcessEmails();
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "fetchInsights") {
    fetchAndProcessEmails().then(sendResponse);
    return true;
  }
});

async function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, function(token) {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(token);
      }
    });
  });
}

async function fetchAndProcessEmails() {
  try {
    const token = await getAuthToken();
    const response = await fetch('http://localhost:5000/get_insights', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token })
    });
    if (!response.ok) {
      throw new Error('Server response was not ok');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching insights:', error);
    return { error: error.message };
  }
}