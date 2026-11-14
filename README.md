# FraudBeacon AI — Explainable Digital Scam Triage

**Competition track:** AI + Finance  
**Interface:** English  
**Project type:** Student research MVP  
**Primary user:** A small-business finance or administration assistant reviewing an unexpected invoice, payment-change or account-security message before paying or sharing account information.

## The problem

Fraudulent messages often imitate trusted banks, delivery services, payment providers, cloud platforms, or colleagues. People need more than a red warning: they need to understand which observable signals caused concern and what safer action to take next.

## What we built

FraudBeacon AI is a local, explainable triage workspace for suspicious message text, visible URLs, basic email headers, attachment filenames, and small CSV batches. Its message analysis combines a scikit-learn text classifier (word- and character-level TF-IDF with Logistic Regression) with a separate rule-based explanation layer. The interface shows the model signal and rule indicators separately, then suggests safer verification steps. The project also includes a short learning lab.

## What is original

We extended the suggested scam-text-filter concept into a multi-input triage workflow with explanations, offline URL parsing, basic header consistency checks, filename-risk checks, batch summaries, and privacy-conscious exports. The included training examples are synthetic and regionally contextual; the application is designed for a global audience, but its model has **not** been validated as a global or multilingual detector.

## Data and evaluation

The bundled classifier was trained on **136 AI-assisted synthetic messages** (72 suspicious, 64 legitimate). A grouped holdout used 100 training rows and 36 test rows. On that small synthetic test set it achieved **83.3% accuracy**, **88.9% precision**, **80.0% recall**, and **84.2% F1** for the suspicious class. The majority-class baseline achieved **55.6% accuracy, 55.6% precision, 100% recall, and 71.4% F1**. The model missed 4 suspicious examples and raised 2 false alarms among 16 legitimate test examples. One miss asked the recipient to share an OTP to cancel a transfer; one false alarm was an Arabic safety reminder telling users not to share passwords or OTPs. The model over-weighted credential keywords and missed protective context. These numbers describe only this synthetic experiment; they are not real-world or international performance estimates.

## Limitations and safe use

This is a prototype, not a production security service. The model score is uncalibrated and is not a probability of fraud. URL inspection checks visible URL structure offline; it does not resolve DNS, follow redirects, visit sites, or query live reputation. Email review is a basic consistency check, not a full SPF/DKIM/DMARC validator. Attachment review inspects filenames only; it does not scan file contents. The app does not block messages or connect to inboxes or banks. Do not enter real passwords, OTPs, PINs, card numbers, account identifiers, or private conversations. Use synthetic examples for public demonstrations.

**This project is a prototype and is not financial advice.**

## Run locally on Windows

1. Install Python 3.11 or 3.12 from <https://www.python.org/downloads/windows/> and enable **Add Python to PATH**.
2. Extract the ZIP to a normal folder.
3. Double-click `START_FRAUDBEACON.bat`.
4. On first run, the launcher creates a virtual environment and installs the requirements. An internet connection is needed for this first setup.
5. Open <http://127.0.0.1:8501> if your browser does not open automatically. Keep the command window open while using the app.

For the competition, share this public GitHub repository as the code link and submit the one-page write-up and optional two-minute demo video. Do **not** ask judges to install the app just to see the demo; record a short screen demonstration using the synthetic examples included here. The competition only requires a viewable GitHub repository or Colab notebook, a one-page write-up, track/team details and credits; a public hosted application URL is not required.

## Reproduce the research experiment

```bash
python -m unittest discover -s tests -v
python train_model.py
```

Optional: `TRAIN_ENGLISH_UCI_MODEL.bat` downloads and trains a separate English SMS spam/ham baseline from the UCI SMS Spam Collection. This optional model is not bundled as a trained model and must not be described as phishing-specific: the UCI spam class includes unwanted messages beyond phishing or financial fraud.

## Credits

- Synthetic training examples: fictional, AI-assisted messages created for this student prototype; no real user messages or personal records are included.
- Machine learning: scikit-learn (TF-IDF + Logistic Regression).
- Application framework: Streamlit; data handling: pandas; model serialization: joblib; numerical operations: NumPy.
- Optional future baseline: Almeida & Hidalgo, *SMS Spam Collection*, UCI Machine Learning Repository, DOI <https://doi.org/10.24432/C5CC84>, CC BY 4.0. It is not included in the current model results.
- AI-assisted development and documentation: ChatGPT (OpenAI).

See `docs/` for the one-page submission write-up, demo script, judge Q&A, failure analysis, scope, and submission checklist. See `data/` for the dataset card and source notes.

## Competition submission files

- One-page write-up PDF: `docs/FraudBeacon_Submission_Writeup.pdf`
- Editable one-page write-up: `docs/FraudBeacon_Submission_Writeup.docx`
- Two-minute demo script: `docs/DEMO_SCRIPT_EN.md`
- Judge Q&A: `docs/JUDGES_QA_EN.md`
- Submission checklist: `docs/SUBMISSION_CHECKLIST.md`
- Compliance review and remaining owner actions: `docs/COMPLIANCE_REVIEW.md`
- Preliminary project-name note: `docs/PROJECT_NAME_NOTE.md`
