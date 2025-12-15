import binaryninja as bn
import logging


def show_consent_upload_dialog():
    """
    Presents the auto-upload consent dialog displaying the required disclosure text.
    This dialog is shown only on first run.
    """

    full_text = (
        "This plugin can be configured to automatically upload samples. "
        "By submitting a file to VirusTotal, you acknowledge that the sample "
        "may be shared with the security community in accordance with "
        "VirusTotal’s Terms of Service and Privacy Policy."
        "\n\n"
        "For more information, see the following links:\n"
        "Terms of Service: https://docs.virustotal.com/docs/terms-of-service\n"
        "Privacy Policy: https://docs.virustotal.com/docs/privacy-policy\n"
    )

    text_label = bn.interaction.LabelField(full_text)

    action_choice = bn.interaction.ChoiceField(
        "Please select your preferred action:",
        [
            "Ok (enable automatic uploads)",
            "No (disable automatic uploads)",
            "Cancel (disable for this session)",
        ],
        default=0,  # default ok
    )

    fields = [
        bn.interaction.LabelField(
            "Welcome to the Beta Version of the unofficial VirusTotal Binary Ninja Plugin!"
        ),
        bn.interaction.SeparatorField(),
        text_label,
        bn.interaction.SeparatorField(),
        action_choice,
    ]

    try:
        if bn.interaction.get_form_input(fields, "VirusTotal Plugin"):
            choice = action_choice.result

            logging.debug(f"[VT] User selected consent choice: {choice}")

            if choice == 0:
                return "ok"
            if choice == 1:
                return "no"
            return "cancel"
        else:
            return "cancel"
    except Exception as e:
        logging.error(f"[VT] Exception showing form input: {e}")
        return "cancel"
