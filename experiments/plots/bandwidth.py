"""Plot mean sent MiB per node per output from selected beacon results."""

from beacon_performance import arguments, draw, load_results, plt


def main():
    args = arguments(__doc__, "beacon-bandwidth.png")
    results = load_results(args.results)
    fig, ax = plt.subplots(figsize=(5, 3.5), layout="constrained")
    draw(ax, results, "bandwidth", "Sent MiB / node / output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()
