#!/usr/bin/env python3
import csv
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path


p = Path('data/power_samples.csv')
p.parent.mkdir(parents=True, exist_ok=True)


if not p.exists():
	raise SystemExit("data/power_samples.csv not found")


ts, watts = [], []
with p.open() as f:
	r = csv.DictReader(f)
	for row in r:
		ts.append(float(row['ts']))
		watts.append(float(row['watts']))


ts = np.array(ts); watts = np.array(watts)
J = np.trapz(watts, ts)
print(f"Energy = {J:.3f} J")


import os
os.makedirs('plots', exist_ok=True)
plt.plot(ts - ts[0], watts)
plt.xlabel('Time (s)'); plt.ylabel('Watts'); plt.title('Power vs time')
plt.tight_layout(); plt.savefig('plots/power.png', dpi=150)
print('Wrote plots/power.png')
