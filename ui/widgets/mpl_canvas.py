import matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Make sure the backend is set to Qt5Agg
matplotlib.use('Qt5Agg')

class MplCanvas(FigureCanvas):
    """A custom Matplotlib canvas widget for PyQt5 integration."""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        # Create a new Matplotlib figure
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super(MplCanvas, self).__init__(fig)