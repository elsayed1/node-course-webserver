import React from 'react';
import classnames from 'classnames';
function TextFieldGroup({
    label,
    errors,
    type,
    id,
    placeholder,
    value,
    name,
    disabled,
    onchange
}) {
  return (
    <div className="form-group">
        <label htmlFor={label}>{label[0].toUpperCase() + label.slice(1, label.length)}</label>
        <input 
        type={type}
        className= {classnames("form-control", {
        'is-invalid': errors[name],
        })}
        id={id}
        name={name}
        aria-describedby="emailHelp" 
        placeholder={placeholder}
        onChange={onchange?onchange:null}
        defaultValue={value} 
        disabled={disabled?disabled:''}
        />
        {errors[name]?(
        <small className='form-text text-danger'>
            {errors[name]}
        </small>
        ):null}
  </div>
  )
}
export default TextFieldGroup;
