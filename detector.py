import numpy as np
from sklearn.ensemble import RandomForestClassifier
import random
import threading
import time

class ThreatDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=15, random_state=42)
        self.pats = []
        self.labs = []
        self.a_types = []
        self._train_base()
        self._start_learn()
    
    def _train_base(self):
        X = [
            [100, 5, 2, 1],
            [200, 10, 3, 2],
            [50, 2, 1, 0],
            [5000, 100, 15, 8],
            [8000, 200, 25, 15],
            [300, 80, 12, 10],
            [1500, 30, 8, 20],
            [500, 5, 25, 2],
            [800, 8, 30, 3]
        ]
        y = [0, 0, 0, 1, 1, 1, 1, 1, 1]
        types = [
            "norm", "norm", "norm",
            "ddos", "ddos", "scan", "scan", "ssh", "ssh"
        ]
        self.pats = X
        self.labs = y
        self.a_types = types
        self.model.fit(X, y)
    
    def _start_learn(self):
        def worker():
            while True:
                time.sleep(20)
                self._gen_learn()
        
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        print("Auto-learning has been launched")
    
    def _gen_learn(self):
        for _ in range(2):
            rnd = random.random()
            if rnd < 0.25:
                p = [
                    random.randint(3000, 15000),
                    random.randint(50, 300),
                    random.randint(5, 20),
                    random.randint(2, 10)
                ]
                lab = 1
                a_t = "ddos"
                
            elif rnd < 0.5:
                p = [
                    random.randint(500, 3000),
                    random.randint(10, 50),
                    random.randint(2, 10),
                    random.randint(15, 40)
                ]
                lab = 1
                a_t = "scan"
                
            elif rnd < 0.75:
                p = [
                    random.randint(300, 2000),
                    random.randint(1, 10),
                    random.randint(20, 50),
                    random.randint(1, 5)
                ]
                lab = 1
                a_t = "ssh"
                
            else:
                p = [
                    random.randint(50, 500),
                    random.randint(1, 20),
                    random.randint(0, 5),
                    random.randint(0, 3)
                ]
                lab = 0
                a_t = "norm"
            
            self.pats.append(p)
            self.labs.append(lab)
            self.a_types.append(a_t)

        self.model.fit(self.pats, self.labs)
        print(f"AI learned {len(self.pats)} patterns")
    
    def _detect_type(self, pkt, ip, sh, pt):
        if pkt > 3000 and ip > 80:
            return "DDoS"
        elif pt > 12:
            return "Scanning"
        elif sh > 15:
            return "SSH атака"
        elif (pkt > 2000 and sh > 10) or (pt > 8 and ip > 50):
            return "Combination attack"
        elif pkt > 1500 or ip > 60 or sh > 8 or pt > 6:
            return "Unknown attack"
        else:
            return "Norm"
    
    def analyze(self, pkt, ip, sh, pt):
        f = [[pkt, ip, sh, pt]]
        pred = self.model.predict(f)[0]
        conf = float(np.max(self.model.predict_proba(f)))
        risk = min((pkt/5000*0.3 + ip/150*0.25 + sh/15*0.25 + pt/10*0.2), 1.0)
        a_t = self._detect_type(pkt, ip, sh, pt)
        
        if pred == 1 or risk > 0.7:
            stat = "ATTACK"
            lvl = "critical"
        elif risk > 0.4:
            stat = "SUSPICIOUS"
            lvl = "warning" 
        else:
            stat = "NORM"
            lvl = "normal"
        
        return {
            "status": stat,
            "level": lvl,
            "confidence": round(conf*100, 1),
            "risk": round(risk*100, 1),
            "patterns": len(self.pats),
            "attack_type": a_t

        }
