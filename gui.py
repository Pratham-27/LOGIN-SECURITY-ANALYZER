import tkinter as tk
from tkinter import filedialog, messagebox

from main import analyze_log


# =============================
# Main Window
# =============================

window = tk.Tk()
window.title("Login Security Analyzer")
window.geometry("850x850")


# =============================
# Variables
# =============================

file_path = tk.StringVar()

total_value = tk.StringVar(value="0")
success_value = tk.StringVar(value="0")
failed_value = tk.StringVar(value="0")

failure_rate_value = tk.StringVar(value="0 %")
risk_value = tk.StringVar(value="-")


# Store latest analysis
current_result = None


# =============================
# Browse File
# =============================

def browse_file():

    filename = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[
            ("Log Files", "*.log"),
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )

    if filename:
        file_path.set(filename)


# =============================
# Analyze Log
# =============================

def analyze_selected_log():

    global current_result

    filename = file_path.get()

    if not filename:
        messagebox.showwarning(
            "No File Selected",
            "Please select a log file first."
        )
        return

    result = analyze_log(filename)

    if result is None:
        messagebox.showerror(
            "Error",
            "Unable to read the selected log file."
        )
        return

    # Save latest result
    current_result = result

    # Update dashboard

    total_value.set(result["total_attempts"])

    success_value.set(result["successful_logins"])

    failed_value.set(result["failed_logins"])

    failure_rate_value.set(
        str(result["failure_rate"]) + " %"
    )

    risk_value.set(result["risk_level"])


    # =============================
    # Suspicious Activity
    # =============================

    suspicious_text.delete("1.0", tk.END)

    if result["suspicious_ips"]:

        for ip, data in result["suspicious_ips"].items():

            suspicious_text.insert(
                tk.END,
                f"IP Address      : {ip}\n"
            )

            suspicious_text.insert(
                tk.END,
                f"Username        : {data['username']}\n"
            )

            suspicious_text.insert(
                tk.END,
                f"Failed Attempts : {data['count']}\n"
            )

            suspicious_text.insert(
                tk.END,
                "Threat           : Possible Brute-Force Activity\n\n"
            )

    else:

        suspicious_text.insert(
            tk.END,
            "No suspicious activity detected."
        )


    # =============================
    # User Analysis
    # =============================

    user_text.delete("1.0", tk.END)

    if result["failed_users"]:

        for username, count in result["failed_users"].items():

            user_text.insert(
                tk.END,
                f"{username} -> {count} failed attempts\n"
            )

    else:

        user_text.insert(
            tk.END,
            "No failed login attempts."
        )


    # =============================
    # IP Analysis
    # =============================

    ip_text.delete("1.0", tk.END)

    if result["failed_attempts"]:

        for ip, data in result["failed_attempts"].items():

            ip_text.insert(
                tk.END,
                f"{ip} -> {data['count']} failed attempts\n"
            )

    else:

        ip_text.insert(
            tk.END,
            "No failed login attempts."
        )


# =============================
# Export Security Report
# =============================

def export_report():

    if current_result is None:

        messagebox.showwarning(
            "No Analysis",
            "Please analyze a log file before exporting the report."
        )

        return

    filename = filedialog.asksaveasfilename(
        title="Save Security Report",
        defaultextension=".txt",
        filetypes=[
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )

    if not filename:
        return


    result = current_result


    # Create report

    report = ""

    report += "========================================\n"
    report += "        LOGIN SECURITY REPORT\n"
    report += "========================================\n\n"

    report += f"Total Login Attempts : {result['total_attempts']}\n"
    report += f"Successful Logins    : {result['successful_logins']}\n"
    report += f"Failed Logins        : {result['failed_logins']}\n"
    report += f"Failure Rate         : {result['failure_rate']} %\n"
    report += f"Risk Level           : {result['risk_level']}\n\n"


    # Suspicious Activity

    report += "----------------------------------------\n"
    report += "SUSPICIOUS ACTIVITY\n"
    report += "----------------------------------------\n\n"

    if result["suspicious_ips"]:

        for ip, data in result["suspicious_ips"].items():

            report += f"IP Address      : {ip}\n"
            report += f"Username        : {data['username']}\n"
            report += f"Failed Attempts : {data['count']}\n"
            report += "Threat          : Possible Brute-Force Activity\n\n"

    else:

        report += "No suspicious activity detected.\n\n"


    # User Analysis

    report += "----------------------------------------\n"
    report += "USER ANALYSIS\n"
    report += "----------------------------------------\n\n"

    if result["failed_users"]:

        for username, count in result["failed_users"].items():

            report += f"{username} -> {count} failed attempts\n"

    else:

        report += "No failed login attempts.\n"


    report += "\n"


    # IP Analysis

    report += "----------------------------------------\n"
    report += "IP ANALYSIS\n"
    report += "----------------------------------------\n\n"

    if result["failed_attempts"]:

        for ip, data in result["failed_attempts"].items():

            report += f"{ip} -> {data['count']} failed attempts\n"

    else:

        report += "No failed login attempts.\n"


    report += "\n"
    report += "========================================\n"
    report += "           END OF REPORT\n"
    report += "========================================\n"


    # Save report

    try:

        with open(filename, "w") as file:
            file.write(report)

        messagebox.showinfo(
            "Report Exported",
            "Security report exported successfully."
        )

    except Exception as error:

        messagebox.showerror(
            "Export Error",
            f"Could not save the report.\n\n{error}"
        )


# =============================
# Clear
# =============================

def clear_results():

    global current_result

    current_result = None

    file_path.set("")

    total_value.set("0")
    success_value.set("0")
    failed_value.set("0")

    failure_rate_value.set("0 %")
    risk_value.set("-")

    suspicious_text.delete("1.0", tk.END)
    user_text.delete("1.0", tk.END)
    ip_text.delete("1.0", tk.END)


# =============================
# Title
# =============================

title_label = tk.Label(
    window,
    text="LOGIN SECURITY ANALYZER",
    font=("Arial", 24, "bold")
)

title_label.pack(pady=20)


# =============================
# File Selection
# =============================

file_label = tk.Label(
    window,
    textvariable=file_path,
    font=("Arial", 10)
)

file_label.pack(pady=5)


browse_button = tk.Button(
    window,
    text="Browse Log File",
    font=("Arial", 11),
    command=browse_file
)

browse_button.pack(pady=5)


analyze_button = tk.Button(
    window,
    text="Analyze Log",
    font=("Arial", 11),
    command=analyze_selected_log
)

analyze_button.pack(pady=5)


# =============================
# Dashboard Cards
# =============================

cards_frame = tk.Frame(window)

cards_frame.pack(pady=20)


# Total Card

total_frame = tk.Frame(
    cards_frame,
    relief="solid",
    borderwidth=1,
    width=200,
    height=100
)

total_frame.grid(row=0, column=0, padx=10)
total_frame.pack_propagate(False)

tk.Label(
    total_frame,
    text="TOTAL",
    font=("Arial", 11, "bold")
).pack(pady=8)

tk.Label(
    total_frame,
    textvariable=total_value,
    font=("Arial", 22, "bold")
).pack()


# Successful Card

success_frame = tk.Frame(
    cards_frame,
    relief="solid",
    borderwidth=1,
    width=200,
    height=100
)

success_frame.grid(row=0, column=1, padx=10)
success_frame.pack_propagate(False)

tk.Label(
    success_frame,
    text="SUCCESSFUL",
    font=("Arial", 11, "bold")
).pack(pady=8)

tk.Label(
    success_frame,
    textvariable=success_value,
    font=("Arial", 22, "bold")
).pack()


# Failed Card

failed_frame = tk.Frame(
    cards_frame,
    relief="solid",
    borderwidth=1,
    width=200,
    height=100
)

failed_frame.grid(row=0, column=2, padx=10)
failed_frame.pack_propagate(False)

tk.Label(
    failed_frame,
    text="FAILED",
    font=("Arial", 11, "bold")
).pack(pady=8)

tk.Label(
    failed_frame,
    textvariable=failed_value,
    font=("Arial", 22, "bold")
).pack()


# =============================
# Risk Level + Failure Rate
# =============================

analysis_frame = tk.Frame(window)
analysis_frame.pack(pady=5)


# Risk Level

risk_section = tk.Frame(
    analysis_frame,
    width=250
)

risk_section.grid(row=0, column=0, padx=50)

tk.Label(
    risk_section,
    text="RISK LEVEL",
    font=("Arial", 12, "bold")
).pack()

tk.Label(
    risk_section,
    textvariable=risk_value,
    font=("Arial", 20, "bold")
).pack(pady=5)


# Failure Rate

rate_section = tk.Frame(
    analysis_frame,
    width=250
)

rate_section.grid(row=0, column=1, padx=50)

tk.Label(
    rate_section,
    text="FAILURE RATE",
    font=("Arial", 12, "bold")
).pack()

tk.Label(
    rate_section,
    textvariable=failure_rate_value,
    font=("Arial", 20, "bold")
).pack(pady=5)


# =============================
# Suspicious Activity
# =============================

suspicious_frame = tk.Frame(
    window,
    relief="solid",
    borderwidth=1
)

suspicious_frame.pack(
    padx=40,
    pady=15,
    fill="x"
)

tk.Label(
    suspicious_frame,
    text="Suspicious Activity",
    font=("Arial", 13, "bold")
).pack(
    anchor="w",
    padx=10,
    pady=8
)

suspicious_text = tk.Text(
    suspicious_frame,
    height=6,
    font=("Courier New", 10)
)

suspicious_text.pack(
    padx=10,
    pady=5,
    fill="x"
)


# =============================
# User Analysis + IP Analysis
# =============================

analysis_boxes = tk.Frame(window)

analysis_boxes.pack(
    padx=40,
    pady=5,
    fill="x"
)


# User Analysis

user_frame = tk.Frame(
    analysis_boxes,
    relief="solid",
    borderwidth=1
)

user_frame.grid(
    row=0,
    column=0,
    padx=5
)

tk.Label(
    user_frame,
    text="User Analysis",
    font=("Arial", 12, "bold")
).pack(
    anchor="w",
    padx=10,
    pady=8
)

user_text = tk.Text(
    user_frame,
    height=5,
    width=35,
    font=("Courier New", 9)
)

user_text.pack(
    padx=10,
    pady=5
)


# IP Analysis

ip_frame = tk.Frame(
    analysis_boxes,
    relief="solid",
    borderwidth=1
)

ip_frame.grid(
    row=0,
    column=1,
    padx=5
)

tk.Label(
    ip_frame,
    text="IP Analysis",
    font=("Arial", 12, "bold")
).pack(
    anchor="w",
    padx=10,
    pady=8
)

ip_text = tk.Text(
    ip_frame,
    height=5,
    width=35,
    font=("Courier New", 9)
)

ip_text.pack(
    padx=10,
    pady=5
)


# =============================
# Buttons
# =============================

buttons_frame = tk.Frame(window)

buttons_frame.pack(pady=15)


clear_button = tk.Button(
    buttons_frame,
    text="Clear",
    font=("Arial", 11),
    command=clear_results
)

clear_button.grid(
    row=0,
    column=0,
    padx=10
)


export_button = tk.Button(
    buttons_frame,
    text="Export Report",
    font=("Arial", 11),
    command=export_report
)

export_button.grid(
    row=0,
    column=1,
    padx=10
)


# =============================
# Start GUI
# =============================

window.mainloop()