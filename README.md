# Keccak-256 Cryptanalysis using AI & Quantum Randomness  

## 🔬 Researching Keccak-256 security using AI & quantum random generators

🚀 **This project investigates Keccak-256 security using AI, procedurally generated data, and quantum random generators.**
My previous research on SHA-256 showed a statistical anomaly in the message scheduler that allows prediction of `w15` values ​​with twice the probability.
Now I'm applying the same methodology to Keccak-256 to identify potential vulnerabilities and make Ethereum more secure.

---

## 🔑 Features & Methodology

**AI-supported cryptanalysis:** Deep learning models with TensorFlow for pattern recognition in Keccak-256

**Quantum random generator:** Generates high-entropic training data to eliminate overfitting

**Procedurally generated data:** Gigabyte-wide data sets for robust training data generation and prevention of overfitting, the training data set includes 300 million hashes

**Cython & low-level C optimization:** Performance boost for extremely high hash rate processing

**SHA-256 findings as a basis:** Extension of the successful SHA-256 analysis to Keccak-256

---


## 📊 First findings from SHA-256 research

**Message Scheduler Anomaly:** The `w15` values ​​can be predicted with **double probability** under certain conditions.

**AI finds correlations:** My models show that there are hidden patterns in SHA-256 that classical cryptography methods do not discover.

**Why is this relevant for Keccak-256?** If a similar structure is found in Keccak, this could **have direct implications for Ethereum security.**

---

## 📥 Installation & Usage

### 🔧 Requirements
- Python 3.10
- TensorFlow 2.18.0
- NumPy, Cython, scikit-learn

### 📌 Installation

```bash
git clone https://github.com/deinusername/sha256-keccak256-research.git
cd sha256-keccak256-research
pip install -r requirements.txt
cd src/
python3.10 setup.py build_ext --inplace
python3.10 training.py
