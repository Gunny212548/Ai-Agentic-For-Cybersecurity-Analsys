from tools.recon import run_recon, save_result

def main():
    target = input("Enter target (IP or domain): ")

    recon_data = run_recon(target)
    save_result(recon_data)

    print("\n[✓] Recon completed")
    print(recon_data)


if __name__ == "__main__":
    main()
