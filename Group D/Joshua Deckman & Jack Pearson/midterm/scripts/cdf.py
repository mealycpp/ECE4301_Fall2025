# cdf.py
import sys, numpy as np, pandas as pd, matplotlib.pyplot as plt
x = np.sort(pd.read_csv(sys.argv[1])['Rekey Time (ms)'].dropna().astype(float).values)
y = np.arange(1, x.size + 1) / x.size
plt.step(x, y, where='post'); plt.xlabel('Latency (ms)'); plt.ylabel('CDF'); plt.grid(True, alpha=.3); plt.tight_layout()
plt.savefig(sys.argv[2] if len(sys.argv) > 2 else 'cdf.png', dpi=200); plt.show()

