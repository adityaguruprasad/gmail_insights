// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getGmailData") {
      // Implement logic to extract data from Gmail interface
      const gmailData = extractGmailData();
      sendResponse({ data: gmailData });
    }
  });
  
  function extractGmailData() {
    // Implement logic to extract relevant data from Gmail interface
    // This is just a placeholder
    return {
      unreadCount: document.querySelectorAll('.bsU').length,
      // Add more relevant data as needed
    };
  }