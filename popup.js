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
    insightsContainer.replaceChildren();

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

      const subject = document.createElement('h3');
      subject.textContent = insight.subject ?? '';

      const sender = document.createElement('p');
      const fromLabel = document.createElement('strong');
      fromLabel.textContent = 'From:';
      sender.append(fromLabel, ' ', insight.sender ?? '');

      const summary = document.createElement('p');
      summary.textContent = insight.summary ?? '';

      div.append(subject, sender, summary);
      insightsContainer.appendChild(div);
    });
  }
});
