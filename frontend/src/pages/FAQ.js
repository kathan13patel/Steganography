import React, { useState } from 'react';
import {Link } from 'react-router-dom';
import './css/FAQ.css';

const FAQ = () => {
    const [activeIndex, setActiveIndex] = useState(null);

    const faqs = [
        {
            question: "How does the steganography work in this app?",
            answer: "Our app uses LSB (Least Significant Bit) encoding combined with AES-256 encryption to hide secret messages within images, audio (WAV files) Each file gets a unique dynamic encryption key for maximum security."
        },
        {
            question: "What file types are supported for steganography?",
            answer: "Images (PNG, JPG), Audio (WAV files only) are supported. Each file type uses optimized LSB encoding for that specific media format."
        },
        {
            question: "How secure are my hidden messages?",
            answer: "Highly secure! Each message is encrypted with a unique 32-byte AES key generated randomly for every file. The encryption happens before the message is hidden using LSB steganography, providing double-layer protection."
        },
        {
            question: "Can anyone detect that a file contains a hidden message?",
            answer: "No. The steganography process modifies media files at a microscopic level, making visual or audible changes virtually undetectable to the human eye or ear."
        },
        {
            question: "How do I encode a secret message into a file?",
            answer: "Go to the encode section, upload your file (image / audio), type your secret message, and click encode. The system will process the file and return a download link for the file containing your hidden message."
        },
        {
            question: "Is the app suitable for sensitive or confidential communication?",
            answer: "Absolutely. The combination of AES encryption and steganography provides a double security layer, making it ideal for sharing sensitive or private information securely."
        }
    ];

    const toggleFAQ = (index) => {
        setActiveIndex(activeIndex === index ? null : index);
    };

    return (
        <div className="faq-container">
            <div className="faq-header">
                <h1>Frequently Asked Questions</h1>
                <p>Learn how to use our secure steganography messaging platform</p>
            </div>
            
            <div className="faq-list">
                {faqs.map((faq, index) => (
                <div 
                    key={index} 
                    className={`faq-item ${activeIndex === index ? 'active' : ''}`}
                    onClick={() => toggleFAQ(index)}>
                    <h3>{faq.question}</h3>
                    <p>{faq.answer}</p>
                </div>
                ))}
            </div>
            
            <div className="" style={{ marginTop: '20px' }}>
                <Link to="/dashboard" className="btn btn-primary"
                    style={{
                        display: 'inline-block',
                        padding: '10px 20px',
                        backgroundColor: '#007bff',
                        color: 'white',
                        textDecoration: 'none',
                        borderRadius: '5px',
                        cursor: 'pointer',
                        fontSize: '16px',
                        textAlign: 'center'}}>
                        <i className="fas fa-home" style={{ marginRight: '8px' }}></i>
                        Back to Home
                </Link>
            </div>
        </div>
    );
};

export default FAQ;