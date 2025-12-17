import binaryninja as bn
import logging
from binaryninjaui import UIContext
import base64
import json
from .ci_notebook import CI_Notebook
from .vtclient import VTClient

class CodeInsightExtractor:

    @staticmethod
    def get_current_view_type():
        """
        Detect the current view type: 
        'disassembled', 'decompiled', or None if unsupported.
        """
        try:
            ctx = UIContext.activeContext()
            if not ctx: 
                return None

            frame = ctx.getCurrentViewFrame()
            if not frame: 
                return None

            view_interface = frame.getCurrentViewInterface()
            if not view_interface: 
                return None

            current_il_type = view_interface.getILViewType()
            current_view_type = current_il_type.view_type
            current_view_name = current_il_type.name

            if current_il_type is None or current_view_type is None:
                return None

            is_disassembly = (current_view_type == bn.FunctionGraphType.NormalFunctionGraph)
            is_decompiled = (current_view_type == bn.FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph) and (current_view_name == 'Pseudo C')

            if is_disassembly:
                return 'disassembled'
            elif is_decompiled:
                return 'decompiled'
            else:
                return None
                
        except Exception as e:
            logging.debug(f"[VT] Error detecting view type: {e}")
            return None

    @staticmethod
    def get_current_code(bv: bn.BinaryView, func: bn.Function):
        """
        Gets the current function's code based on the active view
        (Assembly or Pseudo C).
        """
        view_type = CodeInsightExtractor.get_current_view_type()

        if view_type == 'decompiled':
            return CodeInsightExtractor._get_decompiled_code(func)
        elif view_type == 'disassembled':
            return CodeInsightExtractor._get_disassembly_code(func)
        else:
            return None

    @staticmethod
    def _get_decompiled_code(func: bn.Function) -> str:
        """
        Extracts Pseudo C with function signature.
        """
        lines = []

        # Add function signature using type_tokens (already formatted)
        signature = "".join([token.text for token in func.type_tokens])
        if signature:
            lines.append(signature)

        # Extract the body
        pseudo_c = func.pseudo_c
        if pseudo_c is None:
            return ""

        hlil = pseudo_c.hlil
        if hlil is None:
            return ""

        root = hlil.root
        if root is None:
            return ""

        lines_obj = pseudo_c.get_linear_lines(root)

        for line in lines_obj:
            line_text = "".join([token.text for token in line.tokens])
            lines.append(line_text)

        return "\n".join(lines)

    @staticmethod
    def _get_disassembly_code(func: bn.Function) -> str:
        """
        Extracts linear disassembly with symbols resolved, in linear order.
        """
        lines = []

        # Function name + calling convention if exists
        if func.calling_convention:
            lines.append(f"; Function: {func.name} ({func.calling_convention.name})")
        else:
            lines.append(f"; Function: {func.name}")

        # Collect all basic blocks and sort by start address
        all_blocks = func.basic_blocks

        # Build set of jump targets for labels
        jump_targets = set()
        for block in all_blocks:
            for edge in block.outgoing_edges:
                jump_targets.add(edge.target.start)

        # Process blocks in linear order
        for block in all_blocks:
            block_start = block.start

            # Add label if this block is a jump target (except teh function entry)
            if block_start in jump_targets and block_start != func.start:
                lines.append(f"loc_{block_start:x}:")

            # Iterate using disassembly_text (already includes comments, symbols, etc.)
            for line_obj in block.disassembly_text:
                addr = line_obj.address
                instruction_text = "".join([token.text for token in line_obj.tokens])
                lines.append(f"{addr:#x}: {instruction_text}")

        # Footer
        lines.append(f"; {func.name} endp")

        return "\n".join(lines)


class QueryCodeInsight(bn.BackgroundTaskThread):
    """Background task to query the VirusTotal Code Insight API."""
    
    def __init__(self, api_key: str, code: str, use_codetype: str, ci_notebook: CI_Notebook = None):
        """
        Initializes the QueryCodeInsight background task.

        Args:
            api_key: VirusTotal API key
            code: The source code to analyze
            use_codetype: The type of code being sent ('decompiled' or 'disassembled')
            ci_notebook: Optional notebook instance containing conversation history
        """
        self.api_key = api_key
        self.code = code
        self.use_codetype = use_codetype
        self.ci_notebook = ci_notebook
        self.encoded_src = None
        self._return = None
        self._error_msg = None

        super().__init__(
            initial_progress_text="Analyzing code with VirusTotal Code Insight...",
            can_cancel=True,
        )
        
        if self.use_codetype:
            logging.debug(f'[VT Plugin] Code Insight using src code type: {self.use_codetype}')
        
        if self.code == '':
            logging.error('[VT Plugin] No proper query created for Code Insight')
            self._error_msg = 'No code provided for analysis'


    def get_encoded_src(self):
        """Returns the base64 encoded source code of the query.

        Returns:
            str: The base64 encoded source code.
        """
        return self.encoded_src

    def get_error_msg(self):
        """Returns the error message if the query failed.

        Returns:
            str: The error message, or None if there was no error.
        """
        return self._error_msg
    
    def get_result(self):
        """Returns the result from the Code Insight query.
        
        Returns:
            bytes: The decoded answer from Code Insight (JSON bytes), or None if an error occurred.
        """
        return self._return

    def _process_request(self, query: str) -> str:
        """Encodes the query string in base64.

        Args:
            query: The code to be sent to Code Insight.

        Returns:
            str: The base64 encoded query.
        """
        ci_request = base64.urlsafe_b64encode(query.encode('utf-8'))
        self.encoded_src = ci_request.decode('ascii')
        return self.encoded_src
    
    def _process_output(self, response_text: str):
        """Processes the JSON response from the Code Insight API.

        It decodes the response, checks for errors, and extracts the answer.

        Args:
            response_text: The JSON response from the API as a string.

        Returns:
            bytes: The decoded answer from Code Insight (JSON bytes), or None if an error occurred.
        """
        try:
            json_data = json.loads(response_text)
        except json.JSONDecodeError as e:
            logging.error(f'[VT Plugin] Failed to parse JSON response: {e}')
            self._error_msg = "Invalid JSON response from API"
            return None
        
        answer = json_data.get('data')
        if not answer:
            logging.error('[VT Plugin] No data field in response')
            self._error_msg = "Invalid response structure"
            return None
        
        if 'error' in answer:
            error_content = answer.get('error')
            error_response = {}
            
            # The error content from the API can be a string (sometimes JSON), or a dict.
            if isinstance(error_content, str):
                try:
                    # Try to parse it as JSON
                    error_response = json.loads(error_content)
                    self._error_msg = error_response.get('message', error_content)
                except json.JSONDecodeError:
                    # It's just a plain string
                    self._error_msg = error_content
            elif isinstance(error_content, dict):
                self._error_msg = error_content.get('message', str(error_content))
                error_response = error_content
            else:  # Fallback for other types like None
                self._error_msg = str(error_content)
            
            if 'not_parsed_output' in error_response:
                logging.debug('[VT Plugin] ERROR output: %s', error_response['not_parsed_output'])
            elif 'original_message' in error_response:
                logging.debug('[VT Plugin] ERROR output: %s', error_response['original_message'])
            else:
                logging.debug('[VT Plugin] ERROR message: %s', self._error_msg)
            return None
        
        try:
            decoded_bytes = base64.urlsafe_b64decode(answer)
            return decoded_bytes
        except Exception as e:
            logging.error(f'[VT Plugin] ERROR decoding Code Insight response: {e}')
            self._error_msg = "Failed to decode response"
            return None

    def _build_payload(self) -> dict:
        """Build the API request payload.

        Returns:
            dict: The payload for the Code Insight API, or None if cancelled
        """
        CI_DISASSEMBLED = 'disassembled'
        CI_DECOMPILED = 'decompiled'
        
        payload = {
            'code': self._process_request(self.code),
        }
        
        if self.use_codetype == CI_DECOMPILED:
            payload['code_type'] = CI_DECOMPILED
        else:
            payload['code_type'] = CI_DISASSEMBLED

        # Add conversation history if available
        if self.ci_notebook and self.ci_notebook.get_total():
            self.progress = "Adding conversation history..."
            history = []

            for key in self.ci_notebook.get_functions():
                if self.cancelled:
                    return None
                
                page = self.ci_notebook.get_page(key)
                
                summary = page.get('summary', '')
                description = page.get('description', '')
                
                expected_summary = page.get('expected_summary')
                expected_description = page.get('expected_description')
                
                # Use expected (user-edited) values if available
                if expected_summary:
                    summary = expected_summary
                
                if expected_description:
                    description = expected_description
                
                encoded_response = CI_Notebook.encode_response(summary, description)
                
                history_entry = {
                    'request': page['b64code'],
                    'response': encoded_response
                }
                history.append(history_entry)

            payload['history'] = history
            logging.debug(f'[VT Plugin] Added {len(history)} entries to history')
        
        return payload

    def run(self):
        """The main execution method for the background task.

        Constructs and sends a request to the Code Insight API and processes the
        response. The result is stored in self._return and any error message in
        self._error_msg.
        """        
        self.progress = "Encoding code for analysis..."
        
        # Build payload
        payload = self._build_payload()

        logging.debug('[VT Plugin] Built Code Insight payload', payload)
        
        if payload is None:
            self._error_msg = "Operation cancelled by user"
            self.progress = "Cancelled"
            return
        
        if self.cancelled:
            self._error_msg = "Operation cancelled by user"
            return
        
        logging.debug('[VT Plugin] Sending request to Code Insight')
        self.progress = "Sending request to VirusTotal Code Insight..."

        # Create VT client and send request
        client = VTClient(api_key=self.api_key)
        response_text, error = client.code_insight_analyze(payload)
        
        # Check for network/HTTP errors
        if error:
            self._error_msg = error
            self.progress = "Request failed"
            logging.error(f'[VT Plugin] Code Insight request error: {error}')
            return
        
        if self.cancelled:
            self._error_msg = "Operation cancelled by user"
            return

        # Process successful response
        self.progress = "Processing response..."
        self._return = self._process_output(response_text)
        
        if self._return:
            self.progress = "Code Insight analysis complete"
            logging.info('[VT Plugin] Code Insight analysis completed successfully')
        else:
            # Error was set in _process_output
            self.progress = "Analysis failed - check logs"