from googleapiclient import discovery


def audit_load_balancers(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        compute = discovery.build('compute', 'v1', credentials=google_auth_client, cache_discovery=False)

        def get_name(url=""):
            return url.split('/')[-1]

        request = compute.forwardingRules().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            items = response.get('items', {})

            for _, scoped_list in items.items():
                rules = scoped_list.get('forwardingRules', [])
                for rule in rules:
                    scanned_count += 1
                    lb_name = rule.get('name', 'unknown')
                    target = rule.get('target', '')

                    has_ssl_policy = False
                    has_cloud_armor = False
                    https_redirect = False

                    try:
                        if 'targetHttpsProxies' in target:
                            proxy_name = get_name(target)
                            proxy = compute.targetHttpsProxies().get(
                                project=project_id,
                                targetHttpsProxy=proxy_name
                            ).execute()
                            has_ssl_policy = bool(proxy.get('sslPolicy'))
                            has_cloud_armor = bool(proxy.get('securityPolicy'))

                            if not has_ssl_policy:
                                findings.append({
                                    "id": "GCP-LB-NO-SSL-POLICY",
                                    "severity": "Medium",
                                    "resource": f"Load Balancer ({lb_name})",
                                    "issue": "HTTPS Load Balancer does not have a custom SSL Policy attached, potentially using weak, default ciphers.",
                                    "remediation": "Create and attach an SSL Policy with a minimum TLS version of 1.2 and modern cipher suites."
                                })
                            if not has_cloud_armor:
                                findings.append({
                                    "id": "GCP-LB-NO-CLOUD-ARMOR",
                                    "severity": "High",
                                    "resource": f"Load Balancer ({lb_name})",
                                    "issue": "Load balancer is not protected by Google Cloud Armor security policies.",
                                    "remediation": "Apply a Cloud Armor security policy to protect against DDoS and OWASP Top 10 web attacks."
                                })

                        elif 'targetHttpProxies' in target:
                            proxy_name = get_name(target)
                            proxy = compute.targetHttpProxies().get(
                                project=project_id,
                                targetHttpProxy=proxy_name
                            ).execute()
                            has_cloud_armor = bool(proxy.get('securityPolicy'))

                            if proxy.get('urlMap'):
                                url_map_name = get_name(proxy.get('urlMap'))
                                url_map = compute.urlMaps().get(
                                    project=project_id,
                                    urlMap=url_map_name
                               ).execute()
                                matchers = url_map.get('pathMatchers', [])
                                https_redirect = any(
                                    bool(m.get('defaultRouteAction', {}).get('redirectAction'))
                                    for m in matchers
                                )

                            if not https_redirect:
                                findings.append({
                                    "id": "GCP-LB-NO-HTTPS-REDIRECT",
                                    "severity": "Medium",
                                    "resource": f"Load Balancer ({lb_name})",
                                    "issue": "HTTP Load Balancer does not enforce redirection to HTTPS.",
                                    "remediation": "Update the URL Map to redirect all HTTP traffic to HTTPS."
                                })

                    except Exception:
                        pass

            request = compute.forwardingRules().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as err:
        pass

    return {"findings": findings, "scannedCount": scanned_count}
