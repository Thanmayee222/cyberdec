def evaluate_threat(session_info):
    """
    A simplified threat detection function that looks for suspicious patterns
    In a real system, this would use a proper ML model
    """
    threat_score = 0.0
    activities = session_info['activities']
    
    if len(activities) < 2:
        return 0.1  # Not enough data
    
    # Factor 1: Rapid page visits (bot-like behavior)
    page_visits = [a for a in activities if a['type'] == 'page_visit']
    if len(page_visits) >= 2:
        time_diffs = []
        for i in range(1, len(page_visits)):
            t1 = page_visits[i-1]['timestamp']
            t2 = page_visits[i]['timestamp']
            # Simplified time diff calculation - in real impl would use proper datetime
            time_diffs.append(abs(hash(t2) - hash(t1)) % 10)  # Pseudo-random time diff
        
        if time_diffs and sum(time_diffs)/len(time_diffs) < 2:
            threat_score += 0.3  # Very rapid navigation
    
    # Factor 2: Multiple form submissions
    form_submissions = [a for a in activities if a['type'] == 'form_submission']
    if len(form_submissions) > 1:
        threat_score += 0.2
    
    # Factor 3: Direct access to sensitive endpoints
    sensitive_accesses = [a for a in activities if a['type'] == 'page_visit' and 
                          ('api' in a['data'] or 'admin' in a['data'] or 'logs' in a['data'])]
    if sensitive_accesses:
        threat_score += 0.3
    
    # Factor 4: Unauthorized admin access attempts
    admin_attempts = [a for a in activities if a['type'] == 'unauthorized_admin_access']
    if admin_attempts:
        threat_score += 0.4
    
    return min(1.0, threat_score)  # Cap at 1.0