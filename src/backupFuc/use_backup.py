from src.Manager.qqmusic_decrypt import Decryptor_main as _core_decryptor_main


def Decryptor_main(input_dir="", output_dir="", del_original=False):
    """Backup entrypoint that delegates to the main implementation."""
    return _core_decryptor_main(input_dir=input_dir, output_dir=output_dir, del_original=del_original)
