from frappe.model.document import Document


class KeylessBackupCode(Document):
	def before_insert(self):
		self.used = 0
