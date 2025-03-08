# Keccak-256 Cryptanalysis using AI & Quantum Randomness  

## 🔬 Forschung zur Sicherheit von Keccak-256 mit AI & Quantenzufallsgeneratoren  

🚀 **Dieses Projekt untersucht die Sicherheit von Keccak-256 mithilfe von KI, prozedural generierten Daten und Quantenzufallsgeneratoren.**  
Mein vorheriges Research zu SHA-256 hat eine statistische Anomalie im Message Scheduler gezeigt, die eine Vorhersage von `w15`-Werten mit doppelter Wahrscheinlichkeit ermöglicht.  
Jetzt wende ich dieselbe Methodik auf Keccak-256 an, um potenzielle Schwachstellen zu identifizieren und Ethereum sicherer zu machen.  

---

## 🔑 Features & Methodik  

✅ **AI-gestützte Kryptanalyse:** Deep Learning Modelle mit TensorFlow zur Mustererkennung in Keccak-256  
✅ **Quantenzufallsgenerator:** Erzeugt hochentropische Trainingsdaten zur Eliminierung von Overfitting  
✅ **Prozedural generierte Daten:** Gigabyteweise Datensätze zur robusten Trainingsdatengenerierung  
✅ **Cython & Low-Level C-Optimierung:** Performance-Boost für extrem hohe Hash-Rate Verarbeitung  
✅ **SHA-256 Erkenntnisse als Grundlage:** Erweiterung der erfolgreichen SHA-256 Analyse auf Keccak-256  

---

## 📂 Projektstruktur  

📂 sha256-keccak256-research │── 📄 README.md # Diese Datei │── 📄 LICENSE # Open-Source-Lizenz │── 📄 requirements.txt # Benötigte Python-Pakete │── 📂 src/ # Hauptcode │ │── sha256_research.py # TensorFlow AI-Modell │ │── sha256_extension.pyx # Cython-Bridge zwischen Python & C │ │── sha256_buffer.c # Low-Level C-Implementierung für Hashing & Datenverwaltung │ │── sha256_buffer.h # Header-Datei für C │── 📂 data/ # Externe Datenquellen (optional) │ │── quantum_data_async_len.bin # Großes Quantendaten-Set (extern gehostet)
