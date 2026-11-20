"""Tests for the RandomForest model."""
from detector.model import PhishingModel, get_model


def test_model_trains_on_bundled_data():
    model = get_model()
    assert model.n_samples == 100


def test_phishing_probability_higher_for_phishing_pattern():
    model = get_model()
    phishing = model.phishing_probability("https://paypal.com.secure-login.tk/verify")
    legit = model.phishing_probability("https://www.github.com")
    assert phishing > 0.5
    assert legit < 0.5
    assert phishing > legit


def test_training_is_deterministic():
    first = PhishingModel()
    second = PhishingModel()
    urls = [
        "https://www.github.com",
        "https://paypal.com.secure-login.tk/verify",
        "http://185.220.101.45/paypal/login",
        "https://www.wikipedia.org",
    ]
    for url in urls:
        assert first.phishing_probability(url) == second.phishing_probability(url)


def test_unseen_lookalike_scores_high():
    # A lookalike that is NOT in the training file.
    model = get_model()
    prob = model.phishing_probability("https://micros0ft-secure-login.xyz/verify")
    assert prob > 0.5
