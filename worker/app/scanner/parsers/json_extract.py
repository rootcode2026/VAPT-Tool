import json


def extract_json_document(raw_output: str):
    """
    Extract the first JSON object or array from mixed scanner stdout.

    Docker scanners often print progress logs before structured output.
    """

    if raw_output is None:
        raise ValueError("Scanner output is empty.")

    text = raw_output.strip()

    if not text:
        raise ValueError("Scanner output is empty.")

    decoder = json.JSONDecoder()

    for index, character in enumerate(text):
        if character not in {"{", "["}:
            continue

        try:
            document, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue

        return document

    raise ValueError("JSON document was not found in scanner output.")
