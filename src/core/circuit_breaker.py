def evaluate_and_block(ip, ti_score, priority):
    """Logique de décision critique."""
    final_score = 0
    
    # RÈGLE DU COUPE-CIRCUIT
    # Si Signature Critique (P1) OU TI très élevé (>= 80)
    if priority == 1 or ti_score >= 80:
        final_score = 100
        print(f"----------------------------------------------------------------------------")
        print(f"⛔ [COUPE-CIRCUIT] Menace Critique détectée sur {ip} !")
    else:
        # Calcul pondéré simple pour les autres cas
        final_score = ti_score * 0.5 

    return final_score