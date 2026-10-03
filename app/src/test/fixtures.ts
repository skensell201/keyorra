import type { Item } from "../api";

export function loginItem(overrides: Partial<Item> = {}): Item {
  return {
    id: "i1",
    vault_id: "v1",
    kind: "login",
    title: "GitHub",
    tags: ["dev"],
    favorite: false,
    urls: ["https://github.com/login"],
    fields: [
      { id: "username", label: "username", value: { type: "text", value: "ivan" }, purpose: "username" },
      { id: "password", label: "password", value: { type: "concealed", value: "hunter2" }, purpose: "password" },
    ],
    sections: [
      {
        id: "s1",
        title: "Security",
        fields: [
          { id: "otp", label: "one-time password", value: { type: "totp", value: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" } },
          { id: "exp", label: "expires", value: { type: "month_year", value: 202712 } },
        ],
      },
    ],
    notes: "main account",
    password_history: [],
    attachments: [],
    created_at: 1,
    updated_at: 2,
    ...overrides,
  };
}
