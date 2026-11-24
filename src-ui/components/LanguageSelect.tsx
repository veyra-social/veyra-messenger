import { useTranslation } from "react-i18next";
import { SUPPORTED_UI_LOCALES, type UiLocale } from "../i18n/locale";

type Props = {
  value: UiLocale;
  onChange: (locale: UiLocale) => void;
  id?: string;
  disabled?: boolean;
};

export function LanguageSelect({ value, onChange, id = "ui-language", disabled }: Props) {
  const { t } = useTranslation();

  return (
    <label>
      {t("locale.label")}
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as UiLocale)}
      >
        {SUPPORTED_UI_LOCALES.map((locale) => (
          <option key={locale} value={locale}>
            {t(`locale.${locale}`)}
          </option>
        ))}
      </select>
    </label>
  );
}
