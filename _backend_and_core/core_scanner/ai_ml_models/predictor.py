import os
import re
import google.generativeai as genai

def get_ml_prediction(lexical_features: dict, network_features: dict):
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    if not GEMINI_API_KEY or "yahan" in GEMINI_API_KEY:
        return dummy_math_logic(lexical_features)

    try:
        genai.configure(api_key=GEMINI_API_KEY)
        
        # Google se available models ki list mango (404 Error Fix)
        available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        
        # Jo bhi 'flash' ya 'pro' model free/available ho, usko auto-select karo
        selected_model = None
        for m in available_models:
            if 'flash' in m or 'pro' in m:
                selected_model = m
                break
        
        if not selected_model and available_models:
            selected_model = available_models[0] # Fallback
            
        print(f"🧠 [GEMINI] Auto-selected model: {selected_model}")
        model = genai.GenerativeModel(selected_model) 
        
        # 🔴 THE ULTIMATE FIX: Strict Prompt (AI ko rules samjhana)
        prompt = f"""
        You are a highly logical Cyber Security AI. Analyze these URL features:
        Lexical Details: {lexical_features}
        Network Details: {network_features}
        
        RULES YOU MUST FOLLOW:
        1. If 'is_logger', 'is_webhook', 'is_tunnel' or 'has_ip' is 1, give a HIGH score (80-100).
        2. Missing WHOIS data, "Unknown" registrar, or hidden IP does NOT mean it's malicious. Do not give high scores just for missing info.
        3. If it is a normal educational (.ac.in, .edu, .gov) or commercial domain with no weird symbols, give a LOW score (0-20).
        
        Reply with ONLY the integer number (e.g., 15 or 85). Do not write any other text.
        """
        
        response = model.generate_content(prompt)
        
        # Agar Gemini galti se Text likh de, toh usme se sirf Number kheench lena
        match = re.search(r'\d+', response.text)
        if match:
            score = int(match.group())
        else:
            score = 50 
        
        print(f"🤖 Gemini AI Score: {score}%")
        return min(max(score, 0), 100) 
        
    except Exception as e:
        print(f"⚠️ Gemini AI Error: {e}")
        return dummy_math_logic(lexical_features)

def dummy_math_logic(lexical_features):
    score = 0
    if lexical_features.get('url_length', 0) > 80: score += 15
    if lexical_features.get('has_ip', 0) == 1: score += 40
    if lexical_features.get('count_at', 0) > 0: score += 30
    return min(score, 100)