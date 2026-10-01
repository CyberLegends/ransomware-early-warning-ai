"""Optional development utility; matplotlib is not a runtime dependency."""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ransomware_guard.detector import analyze
from ransomware_guard.fixtures import benign_events, impact_events, precursor_events


def main():
    names = ["Benign office activity", "Elevated precursor signals", "Possible file impact"]
    datasets = [benign_events(), precursor_events(), impact_events()]
    results = [analyze(events)["cases"][0] for events in datasets]
    scores = [case["risk_score"] for case in results]
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12})
    figure, axis = plt.subplots(figsize=(12, 5.7), facecolor="#091526")
    axis.set_facecolor("#091526")
    y = [2, 1, 0]
    axis.barh(y, [100, 100, 100], color="#183047", height=.5)
    axis.barh(y, scores, color=["#69dfca", "#69dfca", "#ffb580"], height=.5)
    for position, score in zip(y, scores):
        axis.text(104, position, str(score) + "/100", color="#e7effb", va="center", fontsize=16, weight="bold")
    axis.set_yticks(y, names, color="#e7effb")
    axis.set_xlim(0, 122)
    axis.set_xticks([0, 20, 40, 60, 80, 100], ["0", "20", "40", "60", "80", "100"], color="#a8bdd2")
    axis.set_xlabel("Heuristic fixture score · not a probability", color="#a8bdd2", labelpad=12)
    axis.spines[["top", "right", "bottom", "left"]].set_visible(False)
    axis.tick_params(length=0)
    figure.text(.035, .93, "CYBER LEGENDS  /  SYNTHETIC LAB RESULTS", color="#69dfca", fontsize=12, weight="bold")
    figure.text(.035, .86, "Constructed scenarios, reproducible outcomes", color="#e7effb", fontsize=23, weight="bold")
    figure.text(.035, .04, "Default rules and lab baseline. These three fixtures do not measure operational accuracy or prevention.", color="#a8bdd2", fontsize=11)
    figure.subplots_adjust(left=.29, right=.90, top=.73, bottom=.20)
    destination = Path(__file__).resolve().parent / "images" / "demo-results.png"
    destination.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(destination, dpi=150, facecolor=figure.get_facecolor())
    plt.close(figure)
    print(destination)


if __name__ == "__main__":
    main()
