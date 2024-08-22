document.addEventListener('DOMContentLoaded', function() {
  const loadingDiv = document.getElementById('loading');
  const errorDiv = document.getElementById('error');
  const insightsContainer = document.getElementById('insights-container');
  const refreshButton = document.getElementById('refreshInsights');

  refreshButton.addEventListener('click', fetchInsights);

  fetchInsights();

  function fetchInsights() {
    loadingDiv.style.display = 'block';
    errorDiv.style.display = 'none';
    insightsContainer.innerHTML = '';

    chrome.runtime.sendMessage({action: "fetchInsights"}, function(response) {
      loadingDiv.style.display = 'none';
      if (response && response.insights) {
        displayInsights(response.insights);
      } else if (response && response.error) {
        errorDiv.textContent = 'Error: ' + response.error;
        errorDiv.style.display = 'block';
      } else {
        errorDiv.textContent = 'An unexpected error occurred';
        errorDiv.style.display = 'block';
      }
    });
  }

  function displayInsights(insights) {
    insights.forEach(insight => {
      const div = document.createElement('div');
      div.className = 'insight';
      div.innerHTML = `
        <h3>${insight.subject}</h3>
        <p><strong>From:</strong> ${insight.sender}</p>
        <p>${insight.summary}</p>
      `;
      insightsContainer.appendChild(div);
    });
  }
});