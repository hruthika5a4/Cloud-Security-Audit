const { google } = require('googleapis');

/**
 * 🌐 Load Balancer (LB) Auditor
 * Checks for SSL Policies, HTTPS Redirects, and Cloud Armor protection.
 */
async function auditLoadBalancers(authClient, projectId) {
  const findings = [];
  let scannedCount = 0;

  try {
    const compute = google.compute({ version: 'v1', auth: authClient });
    const getName = (url = '') => url.split('/').pop();

    let nextPageToken = null;
    do {
      const page = await compute.forwardingRules.aggregatedList({
        project: projectId,
        pageToken: nextPageToken,
      });

      const items = page.data.items || {};

      for (const [, scopedList] of Object.entries(items)) {
        const rules = scopedList.forwardingRules || [];
        for (const rule of rules) {
          scannedCount++;
          const lbName = rule.name;
          const target = rule.target || '';
          
          let hasSslPolicy = false;
          let hasCloudArmor = false;
          let httpsRedirect = false;

          try {
            // Check HTTPS Proxies
            if (target.includes('targetHttpsProxies')) {
              const proxyName = getName(target);
              const proxy = await compute.targetHttpsProxies.get({
                project: projectId,
                targetHttpsProxy: proxyName,
              });
              hasSslPolicy = !!proxy.data.sslPolicy;
              hasCloudArmor = !!proxy.data.securityPolicy;
            } 
            // Check HTTP Proxies for redirects
            else if (target.includes('targetHttpProxies')) {
              const proxyName = getName(target);
              const proxy = await compute.targetHttpProxies.get({
                project: projectId,
                targetHttpProxy: proxyName,
              });
              hasCloudArmor = !!proxy.data.securityPolicy;

              if (proxy.data.urlMap) {
                const urlMap = await compute.urlMaps.get({
                  project: projectId,
                  urlMap: getName(proxy.data.urlMap),
                });
                httpsRedirect = (urlMap.data.pathMatchers || []).some(m => 
                  m.defaultRouteAction?.redirectAction
                );
              }
            }

            // Reports
            if (target.includes('targetHttpsProxies')) {
              if (!hasSslPolicy) {
                findings.push({
                  id: 'GCP-LB-NO-SSL-POLICY',
                  severity: 'Medium',
                  resource: `Load Balancer (${lbName})`,
                  issue: 'HTTPS Load Balancer does not have a custom SSL Policy attached, potentially using weak, default ciphers.',
                  remediation: 'Create and attach an SSL Policy with a minimum TLS version of 1.2 and modern cipher suites.'
                });
              }
              if (!hasCloudArmor) {
                findings.push({
                  id: 'GCP-LB-NO-CLOUD-ARMOR',
                  severity: 'High',
                  resource: `Load Balancer (${lbName})`,
                  issue: 'Load balancer is not protected by Google Cloud Armor security policies.',
                  remediation: 'Apply a Cloud Armor security policy to protect against DDoS and OWASP Top 10 web attacks.'
                });
              }
            }

            if (target.includes('targetHttpProxies') && !httpsRedirect) {
              findings.push({
                id: 'GCP-LB-NO-HTTPS-REDIRECT',
                severity: 'Medium',
                resource: `Load Balancer (${lbName})`,
                issue: 'HTTP Load Balancer does not enforce redirection to HTTPS.',
                remediation: 'Update the URL Map to redirect all HTTP traffic to HTTPS.'
              });
            }

          } catch (e) {
            // Individual LB fetch error
          }
        }
      }
      nextPageToken = page.data.nextPageToken;
    } while (nextPageToken);

  } catch (err) {
    if (err.code !== 403 && err.code !== 404) {
      console.error('[LB Auditor] Error:', err.message);
    }
  }

  return { findings, scannedCount };
}

module.exports = { auditLoadBalancers };
